"""Private child-process services used by the end-to-end experiment."""

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# Running this file directly must find the checked-out library.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


class SampleHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        data = json.dumps({"message": "independent loopback service", "path": self.path}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_):
        pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("kind", choices=["http", "provider"])
    parser.add_argument("--directory", type=Path)
    args = parser.parse_args()
    if args.kind == "http":
        server = ThreadingHTTPServer(("127.0.0.1", 0), SampleHandler)
    else:
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        from saga.provider import Provider
        from saga.provider.server import create_server
        root = args.directory
        provider = Provider(
            json.loads((root / "provider.json").read_text()), root / "state.sqlite",
            load_pem_private_key((root / "pki/provider-key.pem").read_bytes(), password=None),
        )
        server = create_server(
            provider, "127.0.0.1", 0, str(root / "pki/server.pem"),
            str(root / "pki/server-key.pem"), str(root / "pki/ca.pem"),
        )
    print(json.dumps({"port": server.server_address[1]}), flush=True)
    try:
        server.serve_forever(poll_interval=0.1)
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
