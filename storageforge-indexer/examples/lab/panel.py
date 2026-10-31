#!/usr/bin/env python3
"""Local control panel for the KVM lab: Up, Reset, Test and Destroy buttons over lab.sh.

Only this machine can reach it, and a web page elsewhere can't press Destroy: every request needs the token from
the launch URL and a Host header naming this panel, which stops cross-site requests and DNS rebinding.
"""
import argparse
import hmac
import json
import os
import secrets
import subprocess
import threading
import time
import webbrowser
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

HERE = Path(__file__).resolve().parent
LAB = str(HERE / 'lab.sh')
ACTIONS = {'up': ['up'], 'reset': ['reset'], 'test': ['test'], 'destroy': ['down']}
TOKEN_FILE = Path(os.environ.get('XDG_CONFIG_HOME', Path.home() / '.config')) / 'sflab' / 'panel-token'


def token():
    """The token outlives the panel so a bookmarked URL keeps working."""
    TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
    try:
        return TOKEN_FILE.read_text().strip()
    except FileNotFoundError:
        value = secrets.token_urlsafe(32)
        fd = os.open(TOKEN_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(value)
        return value


class Lab:
    def __init__(self):
        self.lock = threading.Lock()
        self.log = deque(maxlen=800)
        self.action = None        # the running action
        self.proc = None
        self.last = None          # {'action', 'ok', 'finished'}
        self.nodes = []
        threading.Thread(target=self._poll_status, daemon=True).start()

    def _poll_status(self):
        while True:
            try:
                out = subprocess.run([LAB, 'status', '--json'], capture_output=True, text=True, timeout=30).stdout
                self.nodes = json.loads(out)
            except (subprocess.SubprocessError, ValueError):
                pass
            time.sleep(3)

    def start(self, action):
        """Destroy is always allowed: lab.sh stops whatever is running first. Anything else waits its turn."""
        with self.lock:
            if self.action and action != 'destroy':
                return False
            self.action = action
            self.log.clear()
            self.log.append(f'$ lab.sh {" ".join(ACTIONS[action])}')
            self.proc = subprocess.Popen([LAB, *ACTIONS[action]], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            threading.Thread(target=self._follow, args=(self.proc, action), daemon=True).start()
        return True

    def _follow(self, proc, action):
        for line in proc.stdout:
            if proc is self.proc:     # an interrupted action's last words don't belong in Destroy's log
                self.log.append(line.rstrip())
        code = proc.wait()
        with self.lock:
            if proc is self.proc:
                self.action = None
                self.last = {'action': action, 'ok': code == 0, 'finished': time.strftime('%H:%M:%S')}

    def state(self):
        return {'action': self.action, 'last': self.last, 'log': list(self.log), 'nodes': self.nodes}


class Handler(BaseHTTPRequestHandler):
    server_version = 'sflab'
    sys_version = ''

    def log_message(self, *args):
        pass

    def _send(self, code, body, ctype='application/json'):
        data = body.encode()
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(data)

    def _allowed(self, supplied):
        s = self.server
        return self.headers.get('Host') in s.hosts and hmac.compare_digest((supplied or '').encode(), s.token.encode())

    def do_GET(self):
        url = urlsplit(self.path)
        if url.path == '/':
            if not self._allowed(parse_qs(url.query).get('t', [''])[0]):
                return self._send(403, 'Open the panel from its launch URL: python3 panel.py --open\n', 'text/plain')
            return self._send(200, PAGE.replace('@TOKEN@', self.server.token), 'text/html; charset=utf-8')
        if url.path == '/api/state':
            if not self._allowed(self.headers.get('X-Lab-Token')):
                return self._send(403, '{"error":"forbidden"}')
            return self._send(200, json.dumps(self.server.lab.state()))
        return self._send(404, '{"error":"not found"}')

    def do_POST(self):
        name = urlsplit(self.path).path.removeprefix('/api/')
        if not self._allowed(self.headers.get('X-Lab-Token')):
            return self._send(403, '{"error":"forbidden"}')
        if name not in ACTIONS:
            return self._send(404, '{"error":"not found"}')
        if not self.server.lab.start(name):
            return self._send(409, '{"error":"another action is running"}')
        return self._send(202, '{"started":true}')


PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>StorageForge Lab</title>
<style>
:root{--bg:#f6f7f8;--panel:#fff;--text:#1c2024;--muted:#60676f;--line:#dfe2e6;--accent:#22577a;--danger:#b3261e;--ok:#1d7a46;--log:#14171a;--logtext:#d7dbe0}
@media (prefers-color-scheme:dark){:root{--bg:#14171a;--panel:#1c2024;--text:#e7eaee;--muted:#98a0a9;--line:#30363c;--accent:#5fa8d3;--danger:#ef6a60;--ok:#57c785;--log:#0d0f11}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.45 system-ui,sans-serif}
main{max-width:880px;margin:0 auto;padding:28px 16px}
h1{font-size:21px;margin:0}.sub{color:var(--muted);margin:2px 0 20px}
.bar{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-bottom:18px}
button{font:inherit;font-weight:600;padding:9px 18px;border-radius:7px;border:1px solid var(--line);background:var(--panel);color:var(--text);cursor:pointer}
button:disabled{opacity:.45;cursor:default}button.main{background:var(--accent);border-color:var(--accent);color:#fff}
@media (prefers-color-scheme:dark){button.main{color:#10151a}}
button.danger{margin-left:auto;background:var(--danger);border-color:var(--danger);color:#fff}
@media (prefers-color-scheme:dark){button.danger{color:#1a0d0c}}
.msg{color:var(--muted);flex-basis:100%}.msg.bad{color:var(--danger)}.msg.good{color:var(--ok)}
.tablewrap{overflow-x:auto;background:var(--panel);border:1px solid var(--line);border-radius:8px;margin-bottom:18px}
table{border-collapse:collapse;width:100%;white-space:nowrap}th,td{text-align:left;padding:8px 12px;border-bottom:1px solid var(--line)}
tr:last-child td{border-bottom:0}th{font-size:12px;color:var(--muted);font-weight:600}
td.mono{font-family:ui-monospace,monospace;font-size:13px}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:7px;background:var(--muted)}.dot.on{background:var(--ok)}
pre{margin:0;padding:12px 14px;background:var(--log);color:var(--logtext);border-radius:8px;height:230px;overflow:auto;font:12.5px/1.5 ui-monospace,monospace;white-space:pre-wrap}
</style></head><body><main>
<h1>StorageForge Lab</h1><p class="sub">Disposable KVM test network. Destroy removes the VMs, network, disks and lab keys straight away, with no confirmation.</p>
<div class="bar"><button class="main" id="up">Up</button><button id="reset">Reset</button><button id="test">Test</button><button class="danger" id="destroy">Destroy</button><div class="msg" id="msg" role="status"></div></div>
<div class="tablewrap"><table><thead><tr><th>VM</th><th>Address</th><th>State</th><th>SSH</th><th>Root FS</th><th>Golden</th></tr></thead><tbody id="rows"></tbody></table></div>
<pre id="log" aria-label="Command output"></pre>
<script>
const T='@TOKEN@',$=id=>document.getElementById(id),H={'X-Lab-Token':T};
const LABEL={up:'Up',reset:'Reset',test:'Test',destroy:'Destroy'};
async function press(a){$('msg').textContent='Starting '+LABEL[a]+'...';$('msg').className='msg';
  const r=await fetch('/api/'+a,{method:'POST',headers:H});if(r.status===409){$('msg').textContent='Another action is running.';$('msg').className='msg bad'}refresh()}
for(const a of Object.keys(LABEL))$(a).onclick=()=>press(a);
function render(s){
  const body=$('rows');body.replaceChildren();
  for(const n of s.nodes){const tr=document.createElement('tr');
    const vals=[n.name,n.ip,n.state,n.ssh,n.rootfs||'-',n.golden];
    vals.forEach((v,i)=>{const td=document.createElement('td');if(i===1)td.className='mono';
      if(i===2){const d=document.createElement('span');d.className='dot'+(v==='running'?' on':'');td.append(d)}
      td.append(v);tr.append(td)});body.append(tr)}
  const exists=s.nodes.some(n=>n.state!=='absent'),golden=s.nodes.length&&s.nodes.filter(n=>n.state!=='absent').every(n=>n.golden==='yes');
  $('up').disabled=!!s.action;$('reset').disabled=!!s.action||!exists||!golden;$('test').disabled=!!s.action||!exists;$('destroy').disabled=s.action==='destroy';
  const m=$('msg');
  if(s.action){m.textContent=LABEL[s.action]+' is running...';m.className='msg'}
  else if(s.last){m.textContent=LABEL[s.last.action]+(s.last.ok?' finished at ':' failed at ')+s.last.finished;m.className='msg '+(s.last.ok?'good':'bad')}
  else{m.textContent='';m.className='msg'}
  const log=$('log'),atEnd=log.scrollHeight-log.scrollTop-log.clientHeight<30,text=s.log.join('\n');
  if(log.textContent!==text){log.textContent=text;if(atEnd)log.scrollTop=log.scrollHeight}
}
async function refresh(){try{const r=await fetch('/api/state',{headers:H});if(r.ok)render(await r.json())}catch(e){$('msg').textContent='The panel has stopped.';$('msg').className='msg bad'}}
refresh();setInterval(refresh,1500);
</script></main></body></html>
"""


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--port', type=int, default=8377)
    ap.add_argument('--open', action='store_true', help='open the panel in the browser, starting it if needed')
    args = ap.parse_args()
    url = f'http://127.0.0.1:{args.port}/?t={token()}'
    try:
        server = ThreadingHTTPServer(('127.0.0.1', args.port), Handler)
    except OSError:               # already running: the launcher only has to show it
        if args.open:
            webbrowser.open(url)
            return
        raise
    server.token = token()
    server.hosts = {f'127.0.0.1:{args.port}', f'localhost:{args.port}'}
    server.lab = Lab()
    print(f'Panel: {url}', flush=True)
    if args.open:
        webbrowser.open(url)
    server.serve_forever()


if __name__ == '__main__':
    main()
