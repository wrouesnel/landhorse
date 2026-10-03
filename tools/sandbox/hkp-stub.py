#!/usr/bin/env python3
"""hkp-stub.py PORT DIR - a fake HKP keyserver for the sandbox.

Keys are the .asc files in DIR. Uploads (POST /pks/add) are saved there as upload-N.asc, so
Publish can be tested without sending anything to a real keyserver. Searches
(GET /pks/lookup?op=index, machine-readable) and downloads (op=get) are answered from
them, using gpg --show-keys, which reads keys without importing them anywhere.
"""
import http.server
import os
import subprocess
import sys
import urllib.parse

port, outdir = int(sys.argv[1]), sys.argv[2]
os.makedirs(outdir, exist_ok=True)


def keys():
    """Yields (fingerprint, [uids], armored) for each stored key."""
    for name in sorted(os.listdir(outdir)):
        path = os.path.join(outdir, name)
        if not name.endswith(".asc"):
            continue
        armored = open(path).read()
        out = subprocess.run(["gpg", "--batch", "--show-keys", "--with-colons", "--fixed-list-mode", path],
                             capture_output=True, text=True).stdout
        fpr, uids, created = None, [], "0"
        for line in out.splitlines():
            f = line.split(":")
            if f[0] == "pub":
                created = f[5]
            elif f[0] == "fpr" and fpr is None:
                fpr = f[9]
            elif f[0] == "uid":
                uids.append(f[9])
        if fpr:
            yield fpr, uids, created, armored


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
        q = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(q.query)
        if q.path != "/pks/lookup":
            self.send_error(404)
            return
        search = params.get("search", [""])[0].lower()
        if search.startswith("0x"):
            search = search[2:]
        found = [k for k in keys() if k[0].lower().endswith(search) or any(search in u.lower() for u in k[1])]
        if not found:
            self.send_error(404)
            return
        op = params.get("op", [""])[0]
        if op == "index":
            lines = [f"info:1:{len(found)}"]
            for fpr, uids, created, _ in found:
                lines.append(f"pub:{fpr}:22:256:{created}::")
                lines += [f"uid:{urllib.parse.quote(u)}:{created}::" for u in uids]
            body = "\n".join(lines) + "\n"
        elif op == "get":
            body = found[0][3]
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *args):
        pass


http.server.HTTPServer(("127.0.0.1", port), Handler).serve_forever()
