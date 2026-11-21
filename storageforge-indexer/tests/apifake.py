"""A platform's HTTPS API on 127.0.0.1 for the API connection tests: a real TLS server with a certificate openssl made, answering
each path from a table of recorded JSON bodies, and writing down every request it got (method, path, headers) so a test can say
what reached it and what did not. Not a mock of the client: the client under test opens real sockets and does real TLS to it."""
import base64
import hashlib
import json
import shutil
import ssl
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote


def make_cert(folder: Path, name: str, cn: str = 'pve.lab') -> tuple[Path, Path, str]:
    """(certificate, key, its SHA-256 fingerprint as openssl prints it)."""
    crt, key = folder / f'{name}.pem', folder / f'{name}.key'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key), '-out', str(crt), '-days', '30',
                    '-subj', f'/CN={cn}', '-addext', f'subjectAltName=DNS:{cn}'], check=True, capture_output=True)
    out = subprocess.run(['openssl', 'x509', '-noout', '-fingerprint', '-sha256', '-in', str(crt)], check=True, capture_output=True, text=True).stdout
    return crt, key, out.strip().split('=', 1)[1]


class RpcFail:
    """A JSON-RPC error the fake answers a call with, in TrueNAS's form."""

    def __init__(self, code: int, message: str, errname: str):
        self.code, self.message, self.errname = code, message, errname


class Platform:
    """routes: path (without /api2/json, query left out) -> body (a dict or list is wrapped as {"data": ...}), or (status, reason, body).
    A callable value is called with the request and gives one of those."""

    def __init__(self, routes: dict | None = None, prefix: str = '/api2/json', wrap: bool = True):
        self.dir = Path(tempfile.mkdtemp(prefix='apifake-'))
        self.routes = dict(routes or {})
        self.prefix, self.wrap = prefix, wrap        # the path every route is under, and whether a body is wrapped as {"data": ...} (Proxmox)
        self.requests: list[dict] = []
        self.calls: list[dict] = []                  # JSON-RPC calls over the WebSocket (TrueNAS), each {'method', 'params'}
        self.methods: dict = {}                      # method -> result, or a callable (params) -> result, or RpcFail
        self.notify_first = False
        self.crt, self.key, self.fingerprint = make_cert(self.dir, 'a')
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(str(self.crt), str(self.key))
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _answer(self):
                if self.headers.get('Upgrade', '').lower() == 'websocket':
                    return self._websocket()
                n = int(self.headers.get('Content-Length') or 0)
                body = self.rfile.read(n) if n else b''
                req = {'method': self.command, 'path': self.path, 'headers': dict(self.headers), 'body': body.decode('utf-8', 'replace')}
                fake.requests.append(req)
                path = self.path.split('?', 1)[0]
                path = unquote(path[len(fake.prefix):] if fake.prefix and path.startswith(fake.prefix) else path)
                got = fake.routes.get(path, (404, 'Not Found', {'data': None}))
                if callable(got):
                    got = got(req)
                status, reason, data, extra = (got + ({},))[:4] if isinstance(got, tuple) else (200, 'OK', got, {})      # a 4th item: more headers (a Location)
                if fake.wrap and not (isinstance(data, dict) and 'data' in data) and not isinstance(data, (str, bytes)):
                    data = {'data': data}
                raw = data if isinstance(data, bytes) else (data.encode() if isinstance(data, str) else json.dumps(data).encode())
                self.send_response(status, reason)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(raw)))
                for k, v in extra.items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(raw)

            def _websocket(self):
                """RFC 6455 as a server: the handshake, then one JSON-RPC answer for each call, until the client closes."""
                fake.requests.append({'method': self.command, 'path': self.path, 'headers': dict(self.headers), 'body': ''})
                if self.path.split('?', 1)[0] != fake.prefix:
                    self.send_response(404, 'Not Found')
                    self.end_headers()
                    return
                accept = base64.b64encode(hashlib.sha1(self.headers['Sec-WebSocket-Key'].encode() + b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest()).decode()
                self.send_response(101, 'Switching Protocols')
                self.send_header('Upgrade', 'websocket')
                self.send_header('Connection', 'Upgrade')
                self.send_header('Sec-WebSocket-Accept', accept)
                self.end_headers()
                self.wfile.flush()
                self.close_connection = True
                while True:
                    head = self.rfile.read(2)
                    if len(head) < 2:
                        return
                    opcode, n = head[0] & 0x0F, head[1] & 0x7F
                    if n == 126:
                        n = int.from_bytes(self.rfile.read(2), 'big')
                    elif n == 127:
                        n = int.from_bytes(self.rfile.read(8), 'big')
                    mask = self.rfile.read(4) if head[1] & 0x80 else b'\0\0\0\0'
                    data = bytes(b ^ mask[i % 4] for i, b in enumerate(self.rfile.read(n)))
                    if opcode == 0x8:
                        return
                    if opcode != 0x1:
                        continue
                    msg = json.loads(data)
                    fake.calls.append({'method': msg['method'], 'params': msg.get('params')})
                    got = fake.methods.get(msg['method'], RpcFail(-32601, 'Method not found', 'ENOMETHOD'))
                    if callable(got) and not isinstance(got, RpcFail):
                        got = got(msg.get('params'))
                    if isinstance(got, RpcFail):
                        answer = {'jsonrpc': '2.0', 'id': msg['id'], 'error': {'code': got.code, 'message': got.message,
                                                                             'data': {'error': 13, 'errname': got.errname, 'reason': got.message, 'trace': None, 'extra': [], 'py_exception': ''}}}
                    else:
                        answer = {'jsonrpc': '2.0', 'id': msg['id'], 'result': got}
                    if fake.notify_first:          # a collection_update before the answer, as TrueNAS sends events unasked
                        self._send(json.dumps({'jsonrpc': '2.0', 'method': 'collection_update', 'params': {'msg': 'changed', 'collection': 'x'}}).encode())
                    self._send(json.dumps(answer).encode())

            def _send(self, payload: bytes):
                n = len(payload)
                head = bytes([0x81]) + (bytes([n]) if n < 126 else bytes([126]) + n.to_bytes(2, 'big') if n < 1 << 16 else bytes([127]) + n.to_bytes(8, 'big'))
                self.wfile.write(head + payload)
                self.wfile.flush()

            do_GET = do_POST = do_PUT = do_DELETE = _answer

        class Server(ThreadingHTTPServer):
            daemon_threads = True

            def handle_error(self, request, client_address):
                pass             # a client that hung up after the handshake (a certificate fetch, a refused pin) is not a failure here

        self.http = Server(('127.0.0.1', 0), Handler)
        self.http.socket = self.ctx.wrap_socket(self.http.socket, server_side=True)
        self.port = self.http.server_address[1]
        self.url = f'https://127.0.0.1:{self.port}'
        threading.Thread(target=self.http.serve_forever, daemon=True).start()

    def new_certificate(self) -> str:
        """The server starts presenting another certificate, as after a renewal or with someone in the middle."""
        crt, key, fp = make_cert(self.dir, 'b', 'other.lab')
        self.ctx.load_cert_chain(str(crt), str(key))
        self.fingerprint = fp
        return fp

    def close(self):
        self.http.shutdown()
        self.http.server_close()
        shutil.rmtree(self.dir, ignore_errors=True)
