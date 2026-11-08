"""Controlled host listener for the isolation test. Answers every request with a canary
and logs the peer address of every connection, so any hit from the sandbox is visible."""
import http.server, socketserver, sys, threading, time

LOG = open("/root/gvisor-evidence/canary-listener.log", "a", buffering=1)

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        LOG.write(f"{time.strftime('%H:%M:%S')} HIT from {self.client_address[0]} to {self.server.server_address[0]}:{self.server.server_address[1]} {self.path}\n")
        body = b"LD-HOST-CANARY-7f3a\n"
        self.send_response(200); self.send_header("content-length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass

class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
    allow_reuse_address = True

for addr in sys.argv[1:]:
    srv = S((addr, 18080), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    LOG.write(f"listening on {addr}:18080\n")
threading.Event().wait()
