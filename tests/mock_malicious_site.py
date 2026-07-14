"""
A tiny local Flask-free HTTP server that serves a page containing
*harmless* obfuscated-JS-shaped patterns and a fake "download" link, so you
can test the whole detection -> decoy-diversion -> reporting pipeline
without pointing the platform at a real malicious site.

This does not exploit anything and does not download real executables —
it only exists to exercise the threat_detection heuristics (eval/unescape/
fromCharCode patterns, a .exe-suffixed link) end to end.

Run:
    python tests/mock_malicious_site.py
Then:
    python src/orchestrator.py --urls http://127.0.0.1:8080 --persona finance_qatar
"""
from http.server import BaseHTTPRequestHandler, HTTPServer

PAGE = b"""<!DOCTYPE html>
<html><head><title>Totally Normal Page</title></head>
<body>
<h1>Nothing to see here</h1>
<script>
// Harmless test pattern shaped like an obfuscation technique, for
// exercising the console-scan heuristic only. Does not do anything.
var s = "aGVsbG8=";
console.log(eval("'hello'"));
console.log(String.fromCharCode(104,105));
document.write(unescape('%68%69'));
</script>
<p>Download the quarterly report:</p>
<a href="/setup_invoice_viewer.exe" download>setup_invoice_viewer.exe</a>
</body></html>
"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.endswith(".exe"):
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", "attachment; filename=setup_invoice_viewer.exe")
            self.end_headers()
            self.wfile.write(b"FAKE_NONFUNCTIONAL_BYTES_FOR_TESTING_ONLY")
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(PAGE)

    def log_message(self, format, *args):
        pass  # quiet


if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", 8080), Handler)
    print("Mock test page at http://127.0.0.1:8080")
    server.serve_forever()
