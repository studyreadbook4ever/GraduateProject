"""Command-line entry points for development provisioning and the Provider."""

import argparse
import signal
import sys

from .config import load_config
from .jsonutil import dumps
from .provider import Provider
from .provision import provision
from .provider.server import create_server


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="saga-cap")
    commands = parser.add_subparsers(dest="command", required=True)
    setup = commands.add_parser("provision", help="create isolated, fresh development certificates and data")
    setup.add_argument("--directory", required=True)
    setup.add_argument("--provider-port", type=int, default=8443)
    setup.add_argument("--http-port", type=int, default=8765)
    serve = commands.add_parser("serve", help="run the mutually authenticated Provider")
    serve.add_argument("--config", required=True)
    serve.add_argument("--state", required=True)
    serve.add_argument("--signing-key", required=True)
    serve.add_argument("--certificate", required=True)
    serve.add_argument("--key", required=True)
    serve.add_argument("--ca", required=True)
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8443)
    args = parser.parse_args(argv)
    try:
        if args.command == "provision":
            print(dumps(provision(args.directory, args.provider_port, args.http_port)))
            return 0
        provider = Provider(load_config(args.config), args.state, args.signing_key)
        server = create_server(provider, args.host, args.port, args.certificate, args.key, args.ca)

        def stop(_signal, _frame):
            raise KeyboardInterrupt

        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        print(dumps({"status": "listening", "host": args.host, "port": server.server_address[1]}), flush=True)
        try:
            server.serve_forever(poll_interval=0.2)
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
        return 0
    except (ValueError, OSError) as exc:
        print(f"saga-cap: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
