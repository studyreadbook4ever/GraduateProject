"""A bounded JSON API over mutually authenticated TLS."""

import hashlib
import socket
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ..errors import ProviderError
from ..jsonutil import dumps, loads
from .core import Provider

MAX_BODY_BYTES = 2_097_152


class _Server(ThreadingHTTPServer):
    daemon_threads = False
    block_on_close = True
    allow_reuse_address = True

    def __init__(self, *args, **kwargs):
        self._slots = threading.BoundedSemaphore(32)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(5)
        try:
            return self.tls_context.wrap_socket(connection, server_side=True), address
        except BaseException:
            connection.close()
            raise


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "saga-cap"
    sys_version = ""

    def log_message(self, *_):
        # Tool calls, tokens and authorization headers never enter request logs.
        pass

    def _reply(self, status: int, value: dict):
        raw = dumps(value).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(raw)
        self.close_connection = True

    def _fingerprint(self) -> str:
        certificate = self.connection.getpeercert(binary_form=True)
        if not certificate:
            raise ProviderError(401, "certificate_required", "client certificate is required")
        return hashlib.sha256(certificate).hexdigest()

    def _body(self) -> dict:
        lengths = self.headers.get_all("Content-Length", [])
        if self.headers.get_all("Transfer-Encoding") or len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdigit():
            raise ProviderError(400, "invalid_body", "one Content-Length and no Transfer-Encoding are required")
        if len(lengths[0]) > 10:
            raise ProviderError(413, "body_too_large", "request exceeds the size limit")
        length = int(lengths[0])
        if length > MAX_BODY_BYTES:
            raise ProviderError(413, "body_too_large", "request exceeds the size limit")
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            raise ProviderError(415, "json_required", "Content-Type must be application/json")
        try:
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError("incomplete request")
            value = loads(raw)
            if not isinstance(value, dict):
                raise ValueError("request body must be an object")
            return value
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise ProviderError(400, "invalid_json", "request body must be unambiguous JSON") from exc

    def _dispatch(self):
        provider: Provider = self.server.provider
        if self.command == "GET" and self.path == "/health":
            return {"status": "ok"}
        fingerprint = self._fingerprint()
        if self.command == "GET" and self.path == "/v1/state":
            return provider.state(fingerprint)
        if self.command == "POST":
            endpoints = {"/v1/rotate": provider.rotate, "/v1/admit": provider.admit, "/v1/finish": provider.finish}
            endpoint = endpoints.get(self.path)
            if endpoint:
                return endpoint(fingerprint, self._body())
        raise ProviderError(404, "unknown_endpoint", "endpoint does not exist")

    def _handle(self):
        try:
            result = self._dispatch()
            self._reply(200, result)
        except ProviderError as exc:
            self._reply(exc.status, exc.as_dict())
        except (TimeoutError, ConnectionError):
            self.close_connection = True
        except Exception:
            self._reply(500, {"error": {"code": "internal_error", "message": "Provider request failed"}})

    do_GET = _handle
    do_POST = _handle


def create_server(provider: Provider, host: str, port: int, certificate, key, ca) -> ThreadingHTTPServer:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(certificate), str(key))
    context.load_verify_locations(cafile=str(ca))
    context.verify_mode = ssl.CERT_REQUIRED
    context.options |= ssl.OP_NO_COMPRESSION
    server_type = _Server
    if ":" in host:
        server_type = type("_IPv6Server", (_Server,), {"address_family": socket.AF_INET6})
    server = server_type((host, port), _Handler)
    server.provider = provider
    server.tls_context = context
    return server
