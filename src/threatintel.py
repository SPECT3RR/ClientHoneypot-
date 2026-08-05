"""
Threat-feed enrichment for observed third-party hosts.

The honeyclient says what a page *did*. A feed says what the wider world has
already seen from that infrastructure. Together they answer a question
neither can alone: was the broker two hops down the ad chain already known
bad before we ever visited?

Providers, in the order they are worth having:

  urlhaus     abuse.ch malware-distribution URLs. Free key from
              auth.abuse.ch; the same key covers ThreatFox. Generous limits,
              so it is the one to set up first.
  threatfox   abuse.ch IOC database. Same abuse.ch key.
  virustotal  70+ engines. Free tier is 4 requests/minute and 500/day, which
              is why the priority ordering in third_party.py matters — the
              quota gets spent on redirect targets, not CDNs.
  otx         AlienVault Open Threat Exchange, free key, generous limits.

Every answer is cached in the database. A free quota is a resource to spend
once, and re-querying a host we already have an answer for is the fastest
way to exhaust it.

Nothing here trusts a single provider. A host is flagged when a provider
reports detections; the dashboard shows which provider said what, because
"VirusTotal: 3/70" and "URLhaus: known malware distribution" are very
different claims and an analyst needs to see which one they have.
"""
import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

USER_AGENT = "ClientHoneypot/1.0 (threat-intel enrichment)"

# Python's bundled CA store on Windows is missing intermediates that several
# feed providers chain through -- abuse.ch fails with CERTIFICATE_VERIFY_FAILED
# while example.com succeeds. certifi ships with httpx, which is already a
# dependency, so this costs nothing.
try:
    import certifi
    _SSL_CONTEXT = ssl.create_default_context(cafile=certifi.where())
except Exception:
    _SSL_CONTEXT = None

# Conservative floors. One engine out of seventy is noise; several is signal.
VT_SUSPICIOUS = 1
VT_MALICIOUS = 3


class RateLimiter:
    """Free tiers are small and unforgiving. Spacing requests is cheaper than
    getting the key throttled."""

    def __init__(self, per_minute: int):
        self.interval = 60.0 / per_minute if per_minute else 0.0
        self._last = 0.0

    def wait(self):
        if not self.interval:
            return
        gap = self.interval - (time.time() - self._last)
        if gap > 0:
            time.sleep(gap)
        self._last = time.time()


def _post_json(url: str, data: dict, headers: dict = None, timeout: int = 20):
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("User-Agent", USER_AGENT)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    with urllib.request.urlopen(req, timeout=timeout,
                                context=_SSL_CONTEXT) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))


def _get_json(url: str, headers: dict = None, timeout: int = 20):
    req = urllib.request.Request(url)
    req.add_header("User-Agent", USER_AGENT)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    with urllib.request.urlopen(req, timeout=timeout,
                                context=_SSL_CONTEXT) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))


# ── providers ──────────────────────────────────────────────────────────────

class Provider:
    name = "base"
    needs_key = False
    per_minute = 30

    def __init__(self, api_key: str = None):
        self.api_key = api_key
        self.limiter = RateLimiter(self.per_minute)

    def available(self) -> bool:
        return bool(self.api_key) if self.needs_key else True

    def lookup(self, host: str) -> dict:
        raise NotImplementedError


class URLhaus(Provider):
    """abuse.ch malware-distribution URLs.

    Was keyless; abuse.ch now returns 401 Unauthorized without an Auth-Key.
    The key is free from auth.abuse.ch and covers ThreatFox as well.
    """
    name = "urlhaus"
    needs_key = True
    per_minute = 60

    def lookup(self, host: str) -> dict:
        self.limiter.wait()
        headers = {"Auth-Key": self.api_key} if self.api_key else {}
        data = _post_json("https://urlhaus-api.abuse.ch/v1/host/",
                          {"host": host}, headers=headers)

        status = data.get("query_status")
        if status == "no_results":
            return {"verdict": "clean", "score": 0,
                    "detail": {"status": status}}
        if status != "ok":
            return {"verdict": "unknown", "score": 0,
                    "detail": {"status": status}}

        urls = data.get("urls") or []
        online = [u for u in urls if u.get("url_status") == "online"]
        tags = sorted({t for u in urls for t in (u.get("tags") or [])})
        return {
            "verdict": "malicious" if urls else "clean",
            "score": len(urls),
            "detail": {"total_urls": len(urls), "online": len(online),
                       "tags": tags[:12],
                       "threat": (urls[0].get("threat") if urls else None),
                       "reference": data.get("urlhaus_reference")},
        }


class VirusTotal(Provider):
    """70+ engines. Free tier 4/min, 500/day — spend it on the shortlist."""
    name = "virustotal"
    needs_key = True
    per_minute = 4

    def lookup(self, host: str) -> dict:
        self.limiter.wait()
        data = _get_json(
            f"https://www.virustotal.com/api/v3/domains/"
            f"{urllib.parse.quote(host)}",
            headers={"x-apikey": self.api_key})

        attrs = (data.get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        flagged = malicious + suspicious

        if malicious >= VT_MALICIOUS:
            verdict = "malicious"
        elif flagged >= VT_SUSPICIOUS:
            verdict = "suspicious"
        else:
            verdict = "clean"

        engines = [name for name, r in (attrs.get("last_analysis_results") or {}).items()
                   if r.get("category") in ("malicious", "suspicious")]
        return {
            "verdict": verdict, "score": flagged,
            "detail": {"malicious": malicious, "suspicious": suspicious,
                       "harmless": stats.get("harmless", 0),
                       "engines": sorted(engines)[:10],
                       "reputation": attrs.get("reputation"),
                       "categories": list((attrs.get("categories") or {}).values())[:5]},
        }


class OTX(Provider):
    """AlienVault OTX. Free key, generous limits, good pulse context."""
    name = "otx"
    needs_key = True
    per_minute = 30

    def lookup(self, host: str) -> dict:
        self.limiter.wait()
        data = _get_json(
            f"https://otx.alienvault.com/api/v1/indicators/domain/"
            f"{urllib.parse.quote(host)}/general",
            headers={"X-OTX-API-KEY": self.api_key})

        pulses = (data.get("pulse_info") or {}).get("pulses") or []
        count = len(pulses)
        return {
            "verdict": "malicious" if count >= 3 else
                       "suspicious" if count >= 1 else "clean",
            "score": count,
            "detail": {"pulses": count,
                       "names": [p.get("name") for p in pulses[:5]],
                       "tags": sorted({t for p in pulses for t in (p.get("tags") or [])})[:10]},
        }


class ThreatFox(Provider):
    """abuse.ch IOC database. Auth key required since 2024."""
    name = "threatfox"
    needs_key = True
    per_minute = 60

    def lookup(self, host: str) -> dict:
        self.limiter.wait()
        data = _post_json("https://threatfox-api.abuse.ch/api/v1/",
                          {"query": "search_ioc", "search_term": host},
                          headers={"Auth-Key": self.api_key})
        if data.get("query_status") != "ok":
            return {"verdict": "clean", "score": 0,
                    "detail": {"status": data.get("query_status")}}
        iocs = data.get("data") or []
        return {"verdict": "malicious" if iocs else "clean",
                "score": len(iocs),
                "detail": {"iocs": len(iocs),
                           "malware": sorted({i.get("malware_printable")
                                              for i in iocs if i.get("malware_printable")})[:8]}}


PROVIDERS = {p.name: p for p in (URLhaus, VirusTotal, OTX, ThreatFox)}


# ── enrichment ─────────────────────────────────────────────────────────────

class Enricher:
    def __init__(self, db, keys: dict = None):
        self.db = db
        self.keys = keys or {}
        self.providers = []
        for name, cls in PROVIDERS.items():
            provider = cls(self.keys.get(name))
            if provider.available():
                self.providers.append(provider)

    def active(self) -> list:
        return [p.name for p in self.providers]

    def missing_keys(self) -> list:
        return [name for name, cls in PROVIDERS.items()
                if cls.needs_key and not self.keys.get(name)]

    def cached(self, host: str) -> list:
        rows = self.db.conn.execute(
            "SELECT * FROM intel_lookups WHERE host = ?", (host,)).fetchall()
        return [{"provider": r["provider"], "verdict": r["verdict"],
                 "score": r["score"], "detail": json.loads(r["detail"]),
                 "checked_ts": r["checked_ts"]} for r in rows]

    def lookup(self, host: str, force: bool = False) -> list:
        """Query every available provider, caching each answer.

        A free quota is spent once. Re-querying a host we already answered is
        the fastest way to exhaust it, so cached results are returned unless
        the caller explicitly forces a refresh.
        """
        results = []
        for provider in self.providers:
            if not force:
                row = self.db.conn.execute(
                    "SELECT * FROM intel_lookups WHERE host = ? AND provider = ?",
                    (host, provider.name)).fetchone()
                if row:
                    results.append({"provider": provider.name,
                                    "verdict": row["verdict"],
                                    "score": row["score"],
                                    "detail": json.loads(row["detail"]),
                                    "cached": True})
                    continue
            try:
                answer = provider.lookup(host)
            except urllib.error.HTTPError as e:
                answer = {"verdict": "error", "score": 0,
                          "detail": {"http": e.code,
                                     "hint": "quota or bad key" if e.code in (204, 401, 403, 429)
                                             else "provider error"}}
            except Exception as e:
                answer = {"verdict": "error", "score": 0,
                          "detail": {"error": type(e).__name__}}

            self.db.conn.execute(
                """INSERT OR REPLACE INTO intel_lookups
                   (host, provider, verdict, score, detail, checked_ts)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (host, provider.name, answer["verdict"], answer["score"],
                 json.dumps(answer["detail"], default=str), time.time()))
            self.db.conn.commit()
            answer["provider"] = provider.name
            answer["cached"] = False
            results.append(answer)
        return results


def consensus(results: list) -> dict:
    """Combine providers without letting one of them speak for all.

    A single engine on VirusTotal is noise; URLhaus listing the host as a
    malware distribution point is not. The worst *substantiated* verdict
    wins, and which provider said it is always carried along, because an
    analyst needs to judge the source as well as the answer.
    """
    real = [r for r in results if r["verdict"] not in ("error", "unknown")]
    if not real:
        return {"verdict": "unknown", "sources": [], "detail": "no provider answered"}

    order = {"clean": 0, "suspicious": 1, "malicious": 2}
    worst = max(real, key=lambda r: order.get(r["verdict"], 0))
    flagged = [r["provider"] for r in real if r["verdict"] in ("malicious", "suspicious")]
    return {
        "verdict": worst["verdict"],
        "by": worst["provider"],
        "flagged_by": flagged,
        "checked_by": [r["provider"] for r in real],
        "score": worst["score"],
    }
