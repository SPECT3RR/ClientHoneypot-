"""
Silent entry gate for the decoy portal.

Easy door, hard house. The leaked credentials simply work — no MFA, no
CAPTCHA, no rate limit. What filters is invisible: submitting the login form
requires a value only a real JS engine can compute, which defeats curl,
requests, and most scanners without the page ever looking instrumented.

A CAPTCHA would be the wrong tool twice over. It deters the human operator we
actually want, and it advertises that the target is defended — telling the
attacker this is a honeypot is the one outcome worth avoiding.

The challenge is deliberately cheap to solve and trivial to reverse-engineer
if anyone bothers. It is a bot filter, not a security control; the security
boundary is the fact that everything behind it is synthetic.
"""
import hashlib
import time

# Rotates hourly so a harvested answer goes stale, without needing state.
WINDOW_SECONDS = 3600


def _secret(window: int) -> str:
    return hashlib.sha256(f"asteria-portal-{window}".encode()).hexdigest()


def expected_answer(window: int = None) -> str:
    window = window if window is not None else int(time.time() // WINDOW_SECONDS)
    return _secret(window)[:16]


def verify(answer: str) -> bool:
    """Accept the current or previous window so a slow human is not locked
    out mid-login by the boundary rolling over."""
    if not answer:
        return False
    now = int(time.time() // WINDOW_SECONDS)
    return answer in (expected_answer(now), expected_answer(now - 1))


def challenge_script() -> str:
    """JS that computes the gate token into the form before submit.

    Uses SubtleCrypto, which exists in every real browser and in no
    HTTP client. Reads as ordinary anti-CSRF plumbing.
    """
    window = int(time.time() // WINDOW_SECONDS)
    return f"""
    (function () {{
      var w = {window};
      function h(s) {{
        var enc = new TextEncoder().encode(s);
        return crypto.subtle.digest('SHA-256', enc).then(function (buf) {{
          return Array.from(new Uint8Array(buf))
            .map(function (b) {{ return b.toString(16).padStart(2, '0'); }})
            .join('').slice(0, 16);
        }});
      }}
      function arm() {{
        var forms = document.querySelectorAll('form');
        if (!forms.length) return;
        h('asteria-portal-' + w).then(function (token) {{
          forms.forEach(function (f) {{
            var existing = f.querySelector('input[name="_ct"]');
            if (existing) {{ existing.value = token; return; }}
            var i = document.createElement('input');
            i.type = 'hidden'; i.name = '_ct'; i.value = token;
            f.appendChild(i);
          }});
        }});
      }}
      if (document.readyState === 'loading') {{
        document.addEventListener('DOMContentLoaded', arm);
      }} else {{ arm(); }}
      setInterval(arm, 2000);
    }})();
    """


BEHAVIOUR_SCRIPT = """
(function () {
  // Mirrors the ownership-manager discriminator: only isTrusted events are
  // evidence of a human. Synthetic events from automation are ignored.
  var moves = [], keys = [], lastKey = null, sent = false;

  function entropy() {
    if (moves.length < 8) return 0;
    var turns = 0;
    for (var i = 2; i < moves.length; i++) {
      var a = moves[i-1][0] - moves[i-2][0], b = moves[i][0] - moves[i-1][0];
      var c = moves[i-1][1] - moves[i-2][1], d = moves[i][1] - moves[i-1][1];
      if ((a > 0) !== (b > 0) || (c > 0) !== (d > 0)) turns++;
    }
    return turns / moves.length;
  }

  function report(kind) {
    try {
      navigator.sendBeacon('/_b', JSON.stringify({
        kind: kind, trusted: true,
        entropy: entropy(), intervals: keys.slice(-12)
      }));
    } catch (e) {}
  }

  document.addEventListener('mousemove', function (e) {
    if (!e.isTrusted) return;
    moves.push([e.clientX, e.clientY]);
    if (moves.length > 60) moves.shift();
    if (!sent && moves.length > 10) { sent = true; report('mousemove'); }
  }, {capture: true, passive: true});

  document.addEventListener('keydown', function (e) {
    if (!e.isTrusted) return;
    var now = performance.now();
    if (lastKey !== null) keys.push(now - lastKey);
    lastKey = now;
    if (keys.length === 6) report('keydown');
  }, {capture: true, passive: true});

  ['click', 'scroll'].forEach(function (t) {
    document.addEventListener(t, function (e) {
      if (e.isTrusted) report(t);
    }, {capture: true, passive: true});
  });
})();
"""
