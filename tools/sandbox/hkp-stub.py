#!/usr/bin/env python3
"""hkp-stub.py PORT DIR - a fake HKP keyserver for the sandbox.

Accepts uploads (POST /pks/add) and saves each to DIR/upload-N.asc, so Publish can be
tested without sending anything to a real keyserver. Lookups always find nothing.
"""
import http.server
import os
import sys
import urllib.parse

port, outdir = int(sys.argv[1]), sys.argv[2]
os.makedirs(outdir, exist_ok=True)


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/pks/add":
            self.send_error(404)
            return
        body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
        keytext = urllib.parse.parse_qs(body).get("keytext", [""])[0]
        n = len(os.listdir(outdir)) + 1
        with open(os.path.join(outdir, f"upload-{n}.asc"), "w") as f:
            f.write(keytext)
        self.send_response(200)
        self.end_headers()

    def do_GET(self):
        self.send_error(404)


http.server.HTTPServer(("127.0.0.1", port), Handler).serve_forever()
