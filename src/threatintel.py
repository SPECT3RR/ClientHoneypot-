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

# HTTP codes that mean "this provider is done for now", not "this host is
# clean". Treating a quota wall as a clean verdict is how a scan silently
# stops finding anything.
EXHAUSTED_CODES = {204, 429}
AUTH_CODES = {401, 403}


class Provider:
    name = "base"
    needs_key = False
    per_minute = 30
    per_day = None          # None = no documented daily cap

    def __init__(self, api_key: str = None):
        self.api_key = api_key
        self.limiter = RateLimiter(self.per_minute)
        self.used_today = 0
        self.exhausted_until = 0.0
        self.last_error = None

    def available(self) -> bool:
        if self.needs_key and not self.api_key:
            return False
        if time.time() < self.exhausted_until:
            return False
        if self.per_day and self.used_today >= self.per_day:
            return False
        return True

    def mark_exhausted(self, seconds: float = 3600, reason: str = "quota"):
        """Stand this provider down so the scan moves to the next one."""
        self.exhausted_until = time.time() + seconds
        self.last_error = reason

    def status(self) -> dict:
        remaining = max(0, self.exhausted_until - time.time())
        return {
            "provider": self.name,
            "has_key": bool(self.api_key) or not self.needs_key,
            "available": self.available(),
            "used_today": self.used_today,
            "per_day": self.per_day,
            "per_minute": self.per_minute,
            "cooldown_seconds": int(remaining),
            "last_error": self.last_error,
        }

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
    per_day = None

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
    per_day = 500

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
    per_day = None

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
    per_day = None

    def lookup(self, host: str) -> dict:
        self.limiter.wait()
        # ThreatFox takes a JSON body, unlike URLhaus which is form-encoded on
        # the same domain. Sending urlencoded returns query_status "no_json",
        # which parsed as "clean" -- so every host came back fine and the feed
        # silently contributed nothing.
        payload = json.dumps({"query": "search_ioc",
                              "search_term": host}).encode()
        req = urllib.request.Request(
            "https://threatfox-api.abuse.ch/api/v1/", data=payload,
            method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Auth-Key", self.api_key)
        req.add_header("User-Agent", USER_AGENT)
        with urllib.request.urlopen(req, timeout=20,
                                    context=_SSL_CONTEXT) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))

        status = data.get("query_status")
        if status in ("no_result", "no_results"):
            return {"verdict": "clean", "score": 0, "detail": {"status": status}}
        if status != "ok":
            # Never "clean": a malformed request reading as "nothing found" is
            # how a feed stops contributing without anyone noticing.
            return {"verdict": "unknown", "score": 0, "detail": {"status": status}}
        # search_ioc is a substring search: it returns every IOC that merely
        # MENTIONS the term. Unfiltered, google.com came back with 33 IOCs and
        # a "malicious" verdict. Only an IOC that IS this host counts.
        exact = [i for i in (data.get("data") or [])
                 if self._is_exact(i, host)]
        return {"verdict": "malicious" if exact else "clean",
                "score": len(exact),
                "detail": {"iocs": len(exact),
                           "considered": len(data.get("data") or []),
                           "malware": sorted({i.get("malware_printable")
                                              for i in exact
                                              if i.get("malware_printable")})[:8]}}

    @staticmethod
    def _is_exact(ioc: dict, host: str) -> bool:
        value = (ioc.get("ioc") or "").strip().lower()
        host = host.lower()
        kind = (ioc.get("ioc_type") or "").lower()
        if not value:
            return False
        if kind in ("domain", "hostname"):
            return value == host
        if kind in ("url",):
            return urllib.parse.urlparse(value).netloc.split(":")[0] == host
        return False


class URLScan(Provider):
    """urlscan.io. Free key, 100 searches/day, rich page-level context."""
    name = "urlscan"
    needs_key = True
    per_minute = 30
    per_day = 100

    def lookup(self, host: str) -> dict:
        self.limiter.wait()
        query = urllib.parse.quote(f'page.domain:"{host}"')
        data = _get_json(
            f"https://urlscan.io/api/v1/search/?q={query}&size=20",
            headers={"API-Key": self.api_key})

        results = data.get("results") or []
        malicious = [r for r in results
                     if ((r.get("verdicts") or {}).get("overall") or {}).get("malicious")]
        tags = sorted({t for r in results
                       for t in (((r.get("verdicts") or {}).get("overall") or {})
                                 .get("categories") or [])})
        return {
            "verdict": "malicious" if malicious else
                       "suspicious" if results and tags else "clean",
            "score": len(malicious),
            "detail": {"scans": len(results), "malicious_scans": len(malicious),
                       "categories": tags[:8],
                       "reference": f"https://urlscan.io/search/#{host}"},
        }


class SafeBrowsing(Provider):
    """Google Safe Browsing. 10,000 requests/day -- the most generous of the
    set, which makes it the natural fallback when VirusTotal runs dry."""
    name = "safebrowsing"
    needs_key = True
    per_minute = 60
    per_day = 10000

    THREATS = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
               "POTENTIALLY_HARMFUL_APPLICATION"]

    def lookup(self, host: str) -> dict:
        self.limiter.wait()
        body = json.dumps({
            "client": {"clientId": "clienthoneypot", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": self.THREATS,
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": f"http://{host}/"},
                                  {"url": f"https://{host}/"}],
            },
        }).encode()

        req = urllib.request.Request(
            "https://safebrowsing.googleapis.com/v4/threatMatches:find"
            f"?key={urllib.parse.quote(self.api_key)}",
            data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("User-Agent", USER_AGENT)
        with urllib.request.urlopen(req, timeout=20,
                                    context=_SSL_CONTEXT) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))

        matches = data.get("matches") or []
        kinds = sorted({m.get("threatType") for m in matches if m.get("threatType")})
        return {"verdict": "malicious" if matches else "clean",
                "score": len(matches),
                "detail": {"matches": len(matches), "threat_types": kinds}}


PROVIDERS = {p.name: p for p in (URLhaus, VirusTotal, OTX, ThreatFox,
                                 URLScan, SafeBrowsing)}


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

    def status(self) -> list:
        """Per-provider quota and cooldown, so a thin scan is explainable."""
        return [p.status() for p in self.providers]

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
            if not provider.available():
                continue          # exhausted or unauthenticated: next one
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
                provider.used_today += 1
                provider.last_error = None
            except urllib.error.HTTPError as e:
                if e.code in EXHAUSTED_CODES:
                    # Out of quota, not a clean host. Stand this provider down
                    # for an hour; the others carry the scan.
                    provider.mark_exhausted(3600, f"HTTP {e.code} quota")
                    answer = {"verdict": "error", "score": 0,
                              "detail": {"http": e.code, "hint": "quota exhausted",
                                         "cooldown": "1h"}}
                elif e.code in AUTH_CODES:
                    # A bad key never recovers on its own. Stand it down for
                    # the session rather than burning every host on 401s.
                    provider.mark_exhausted(86400, f"HTTP {e.code} auth")
                    answer = {"verdict": "error", "score": 0,
                              "detail": {"http": e.code,
                                         "hint": "key rejected — check or replace it"}}
                else:
                    answer = {"verdict": "error", "score": 0,
                              "detail": {"http": e.code, "hint": "provider error"}}
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
