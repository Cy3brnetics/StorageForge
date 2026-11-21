"""A platform's HTTPS API on 127.0.0.1 for the API connection tests: a real TLS server with a certificate openssl made, answering
each path from a table of recorded JSON bodies, and writing down every request it got (method, path, headers) so a test can say
what reached it and what did not. Not a mock of the client: the client under test opens real sockets and does real TLS to it."""
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


class Platform:
    """routes: path (without /api2/json, query left out) -> body (a dict or list is wrapped as {"data": ...}), or (status, reason, body).
    A callable value is called with the request and gives one of those."""

    def __init__(self, routes: dict | None = None):
        self.dir = Path(tempfile.mkdtemp(prefix='apifake-'))
        self.routes = dict(routes or {})
        self.requests: list[dict] = []
        self.crt, self.key, self.fingerprint = make_cert(self.dir, 'a')
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(str(self.crt), str(self.key))
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _answer(self):
                n = int(self.headers.get('Content-Length') or 0)
                body = self.rfile.read(n) if n else b''
                req = {'method': self.command, 'path': self.path, 'headers': dict(self.headers), 'body': body.decode('utf-8', 'replace')}
                fake.requests.append(req)
                path = self.path.split('?', 1)[0]
                path = unquote(path[len('/api2/json'):] if path.startswith('/api2/json') else path)
                got = fake.routes.get(path, (404, 'Not Found', {'data': None}))
                if callable(got):
                    got = got(req)
                status, reason, data = got if isinstance(got, tuple) else (200, 'OK', got)
                if not (isinstance(data, dict) and 'data' in data) and not isinstance(data, (str, bytes)):
                    data = {'data': data}
                raw = data if isinstance(data, bytes) else (data.encode() if isinstance(data, str) else json.dumps(data).encode())
                self.send_response(status, reason)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

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
