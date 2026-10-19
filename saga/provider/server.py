"""A bounded JSON API over mutually authenticated TLS."""

import hashlib
import io
import socket
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from ..errors import ProviderError
from ..config import path_string
from ..jsonutil import dumps, loads
from .core import Provider

MAX_BODY_BYTES = 2_097_152
MAX_FINISH_BODY_BYTES = 5 * 1024 * 1024
HANDSHAKE_TIMEOUT_SECONDS = 5
REQUEST_TIMEOUT_SECONDS = 5


class _DeadlineReader(io.RawIOBase):
    """Bound total request parsing time, including peers that keep trickling."""

    def __init__(self, connection, deadline):
        super().__init__()
        self.connection = connection
        self.deadline = deadline

    def readable(self):
        return True

    def readinto(self, buffer):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("request deadline expired")
        timeout = self.connection.gettimeout()
        self.connection.settimeout(min(timeout, remaining) if timeout is not None else remaining)
        return self.connection.recv_into(buffer)


class _Server(ThreadingHTTPServer):
    daemon_threads = False
    block_on_close = True
    allow_reuse_address = True

    def __init__(self, *args, **kwargs):
        self._slots = threading.BoundedSemaphore(32)
        self._connections = set()
        self._connections_lock = threading.Lock()
        self._closing = False
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self._failure(ProviderError(503, "server_busy", "request capacity reached"), nonblocking=True)
            self.shutdown_request(request)
            return
        try:
            with self._connections_lock:
                if self._closing:
                    self._slots.release()
                    self.shutdown_request(request)
                    return
                self._connections.add(request)
            super().process_request(request, client_address)
        except BaseException:
            with self._connections_lock:
                self._connections.discard(request)
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        connection = request
        try:
            # Handshakes consume a bounded worker slot, never the accept loop.
            with self._connections_lock:
                if self._closing:
                    return
                connection = self.tls_context.wrap_socket(request, server_side=True, do_handshake_on_connect=False)
                self._connections.discard(request)
                self._connections.add(connection)
            connection.settimeout(HANDSHAKE_TIMEOUT_SECONDS)
            try:
                connection.do_handshake()
            except (OSError, TimeoutError):
                self._failure(ProviderError(401, "tls_failed", "TLS handshake failed"))
                return
            # An otherwise valid CA certificate does not get to hold a slot
            # while supplying an incomplete HTTP request indefinitely.
            if self._enrolled(connection):
                connection.settimeout(REQUEST_TIMEOUT_SECONDS)
                self.finish_request(connection, client_address)
        except Exception:
            self.handle_error(connection, client_address)
        finally:
            self.shutdown_request(connection)
            with self._connections_lock:
                self._connections.discard(request)
                self._connections.discard(connection)
            self._slots.release()

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(HANDSHAKE_TIMEOUT_SECONDS)
        return connection, address

    def _enrolled(self, connection):
        with self.provider.request_context("unknown") as context:
            try:
                certificate = connection.getpeercert(binary_form=True)
                self.provider._agent(hashlib.sha256(certificate).hexdigest())
                return True
            except ProviderError as error:
                try:
                    self.provider.record_failure(error)
                except ProviderError as audit_error:
                    error = audit_error
                value = error.as_dict()
                value["error"]["request_id"] = context["request_id"]
                raw = dumps(value).encode("utf-8")
                reason = "Forbidden" if error.status == 403 else "Service Unavailable"
                response = (
                    f"HTTP/1.1 {error.status} {reason}\r\n"
                    "Content-Type: application/json; charset=utf-8\r\n"
                    f"Content-Length: {len(raw)}\r\n"
                    f"X-Saga-Request-ID: {context['request_id']}\r\n"
                    "Cache-Control: no-store\r\nConnection: close\r\n\r\n"
                ).encode("ascii")
                connection.sendall(response + raw)
                return False

    def server_close(self):
        with self._connections_lock:
            self._closing = True
            for connection in self._connections:
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                connection.close()
        super().server_close()

    def _failure(self, error, *, nonblocking=False):
        try:
            self.provider.record_failure(error, nonblocking=nonblocking)
        except ProviderError:
            # record_failure already emitted its redacted emergency event.
            pass

    def handle_error(self, request, client_address):
        # The base implementation prints exception text and traceback paths.
        self._failure(ProviderError(500, "internal_error", "request handler failed"))


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "saga-cap"
    sys_version = ""

    def setup(self):
        super().setup()
        self.rfile.close()
        self.rfile = io.BufferedReader(_DeadlineReader(
            self.connection, time.monotonic() + REQUEST_TIMEOUT_SECONDS,
        ))

    def log_message(self, *_):
        # Tool calls, tokens and authorization headers never enter request logs.
        pass

    def log_error(self, *_):
        # The HTTP parser consumes header/request-line timeouts before dispatch.
        # Its format arguments may contain private data or exception text.
        provider: Provider = self.server.provider
        with provider.request_context("unknown"):
            try:
                provider._agent(self._fingerprint())
            except ProviderError:
                pass
            provider.phase("parsing")
            try:
                provider.record_failure(ProviderError(408, "transport_error", "request parsing failed"))
            except ProviderError:
                pass

    def _reply(self, status: int, value: dict):
        raw = dumps(value).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        if getattr(self, "_request_id", None):
            self.send_header("X-Saga-Request-ID", self._request_id)
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
        limit = MAX_FINISH_BODY_BYTES if self.path == "/v1/finish" else MAX_BODY_BYTES
        if length > limit:
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
        # Attribute malformed bodies to the authenticated identity, too.
        provider._agent(fingerprint)
        path = urlsplit(self.path).path
        if self.command == "GET" and self.path == "/v1/state":
            return provider.state(fingerprint)
        if self.command == "GET" and path in {"/v1/audit", "/v1/failures"}:
            provider.phase("parsing")
            try:
                parsed = urlsplit(self.path)
                query = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
                if parsed.fragment or not query.keys() <= {"after", "limit"} or any(len(values) != 1 or not values[0].isascii() or not values[0].isdigit() or len(values[0]) > 19 for values in query.values()):
                    raise ValueError
                after = int(query.get("after", ["0"])[0])
                limit = int(query.get("limit", ["100"])[0])
            except ValueError:
                raise ProviderError(400, "invalid_pagination", "audit pagination is invalid") from None
            endpoint = provider.audit_events if path == "/v1/audit" else provider.failure_events
            events = endpoint(fingerprint, after=after, limit=limit)
            return {"events": events, "next_after": events[-1]["event_id"] if events else after}
        if self.command == "POST":
            endpoints = {"/v1/rotate": provider.rotate, "/v1/revoke": provider.revoke, "/v1/admit": provider.admit, "/v1/finish": provider.finish, "/v1/operation": provider.operation}
            endpoint = endpoints.get(self.path)
            if endpoint:
                provider.phase("parsing")
                return endpoint(fingerprint, self._body())
        raise ProviderError(404, "unknown_endpoint", "endpoint does not exist")

    def _handle(self):
        provider: Provider = self.server.provider
        operation = {
            "/health": "health", "/v1/state": "state", "/v1/rotate": "rotate",
            "/v1/revoke": "revoke", "/v1/admit": "admit", "/v1/finish": "finish",
            "/v1/audit": "audit", "/v1/failures": "failures",
            "/v1/operation": "operation",
        }.get(self.path.split("?", 1)[0], "unknown")
        with provider.request_context(operation) as context:
            self._request_id = context["request_id"]
            try:
                if self.path != "/health":
                    provider._agent(self._fingerprint())
                provider.phase("parsing")
                call_ids = self.headers.get_all("X-Saga-Call-ID", [])
                if len(call_ids) > 1:
                    raise ProviderError(400, "invalid_call_id", "only one X-Saga-Call-ID is allowed")
                if call_ids:
                    provider.set_call_id(call_ids[0])
                result = self._dispatch()
                provider.phase("response")
                self._reply(200, result)
            except Exception as exc:
                try:
                    provider.record_failure(exc)
                except ProviderError as audit_error:
                    exc = audit_error
                if isinstance(exc, (TimeoutError, ConnectionError)):
                    self.close_connection = True
                    return
                if isinstance(exc, ProviderError):
                    status, value = exc.status, exc.as_dict()
                else:
                    status, value = 500, {"error": {"code": "internal_error", "message": "Provider request failed"}}
                value["error"]["request_id"] = self._request_id
                try:
                    self._reply(status, value)
                except (OSError, TimeoutError):
                    self.close_connection = True

    def send_error(self, code, message=None, explain=None):
        # Parser/unsupported-method diagnostics must not echo request-line text.
        provider: Provider = self.server.provider
        with provider.request_context("unknown") as context:
            self._request_id = context["request_id"]
            try:
                provider._agent(self._fingerprint())
            except ProviderError:
                # A malformed request need not have an enrolled peer identity.
                pass
            call_ids = self.headers.get_all("X-Saga-Call-ID", []) if hasattr(self, "headers") else []
            if len(call_ids) == 1:
                try:
                    provider.set_call_id(call_ids[0])
                except ProviderError:
                    pass
            provider.phase("parsing")
            error = ProviderError(code if 400 <= code <= 599 else 400, "invalid_http", "HTTP request is unsupported or malformed")
            try:
                provider.record_failure(error)
            except ProviderError as audit_error:
                error = audit_error
            value = error.as_dict()
            value["error"]["request_id"] = self._request_id
            try:
                self._reply(error.status, value)
            except (OSError, TimeoutError):
                self.close_connection = True

    do_GET = _handle
    do_POST = _handle


def create_server(provider: Provider, host: str, port: int, certificate, key, ca) -> ThreadingHTTPServer:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(path_string(certificate, "TLS certificate path"), path_string(key, "TLS key path"))
    context.load_verify_locations(cafile=path_string(ca, "TLS CA path"))
    context.verify_mode = ssl.CERT_REQUIRED
    context.options |= ssl.OP_NO_COMPRESSION
    server_type = _Server
    if ":" in host:
        server_type = type("_IPv6Server", (_Server,), {"address_family": socket.AF_INET6})
    server = server_type((host, port), _Handler)
    server.provider = provider
    server.tls_context = context
    return server
