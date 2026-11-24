'use strict';
(() => {
  const places = {
    '#tab-search': 'search folders report export-markdown', '#tab-jobs': 'scan access hosts remote',
    '#tab-copies': 'copies dupes', '#tab-moves': 'archive moves', '#tab-git': 'git',
    '#tab-infra': 'vm docker sfnet shares site', '#tab-changes': 'changes plan blueprint graph canvas',
    '#tab-rebuild': 'clone', '#tab-deploy': 'deploy tasks schedule',
    '#ad-sec-users': 'user', '#ad-sec-keys': 'vault rotate', '#ad-sec-audit': 'audit backup restore',
    '#ad-sec-maintenance': 'config reset prune migrate serve healthcheck',
  };
  if (location.pathname === '/security') places['main'] = 'clamav';
  if (location.pathname === '/logs') places['main'] = 'log hostlogs';
  const node = sfNode;
  const opt = (name, value) => new Option(name, value);
  let catalog;
  function encode(line) {
    return btoa(Array.from(new TextEncoder().encode(line), (b) => String.fromCharCode(b)).join(''));
  }
  const quote = (arg) => "'" + arg.replaceAll("'", "'\"'\"'") + "'";
  async function mount(box, families) {
    const [commands, me, hosts] = await Promise.all([
      catalog || (catalog = getJSON('/api/cli/catalog').catch((e) => { catalog = null; throw e; })),
      sfMe(), getJSON('/api/hosts')
    ]);
    const items = commands.commands.filter((c) => families.includes(c.path[0]));
    const select = node('select', { 'aria-label': 'Operation' }, ...items.map((c, i) => opt(c.path.join(' › '), i)));
    const host = node('select', { required: true, 'aria-label': 'Execution host' }, opt('Choose a host with StorageForge installed', ''),
      ...hosts.indexed.map((h) => opt(h.hostname, h.hostname)));
    const account = node('input', { placeholder: 'Monitoring-only host account (if required)', 'aria-label': 'SSH account' });
    const fields = node('div', { class: 'stack' });
    const output = node('pre', { 'aria-label': 'Command output', tabindex: 0 });
    output.style.maxHeight = '24rem'; output.style.overflow = 'auto';
    const status = node('p', { role: 'status' });
    const run = node('button', { type: 'submit', class: 'btn pri' }, 'Run');
    const allowed = (me.permissions || []).includes('console.open');
    run.disabled = !allowed;
    if (!allowed) status.textContent = 'Running host commands requires console access.';
    const stop = node('button', { type: 'button', hidden: true }, 'End session');
    const answer = node('input', { type: 'password', autocomplete: 'off', 'aria-label': 'Response to command prompt' });
    const reply = node('form', { hidden: true }, answer, node('button', { type: 'submit' }, 'Send response'));
    const form = node('form', { class: 'stack' }, select, host, account, fields, run);
    let readers, sid;
    function draw() {
      readers = [];
      const required = [], optional = [];
      const c = items[select.value];
      c.levels.forEach((level, i) => {
        if (i) readers.push(() => [c.path[i - 1]]);
        for (const f of level) {
          const input = f.choices.length ? node('select', {}, opt('', ''), ...f.choices.map((v) => opt(v, v))) :
            f.repeat ? node('textarea', {}) : node('input', { type: f.toggle ? 'checkbox' : f.numeric ? 'number' : 'text' });
          input.required = f.required;
          if (f.numeric) input.step = f.integer ? '1' : 'any';
          const label = f.name.replaceAll('_', ' ') + (f.repeat ? ' (one per line)' : '');
          (f.required ? required : optional).push(node('label', { class: 'field col' }, label, input, node('small', {}, f.help)));
          readers.push(() => {
            if (f.toggle) return input.checked ? [f.flag] : [];
            const values = f.repeat ? input.value.split('\n').filter(Boolean) : input.value ? [input.value] : [];
            return values.map((v) => f.flag ? f.flag + '=' + v : v);
          });
        }
      });
      fields.replaceChildren(...required, node('details', {}, node('summary', {}, 'Options'), ...optional));
    }
    select.onchange = draw;
    draw();
    const input = (value) => postJSON('/api/console/sessions/' + sid + '/input', { data: encode(value + '\r') });
    reply.onsubmit = async (ev) => {
      ev.preventDefault(); const value = answer.value; answer.value = '';
      try { await input(value); } catch (e) { status.textContent = e.message; }
    };
    stop.onclick = async () => {
      try { await api('/api/console/sessions/' + sid, { method: 'DELETE' }); } catch (e) { status.textContent = e.message; }
    };
    form.onsubmit = async (ev) => {
      ev.preventDefault();
      if (run.disabled) return;
      const args = readers.flatMap((read) => read());
      if (args.some((v) => /[\x00-\x1f\x7f]/.test(v))) { status.textContent = 'Control characters are unsupported in command arguments.'; return; }
      run.disabled = true; output.textContent = ''; status.textContent = 'Connecting to ' + host.value;
      try {
        const res = await postJSON('/api/console/sessions', { host: host.value, user: account.value.trim(), kind: 'ssh', route: 'auto' });
        sid = (await res.json()).id;
        await input('exec storageforge-index ' + args.map(quote).join(' '));
        reply.hidden = stop.hidden = false;
        status.textContent = 'Running on ' + host.value;
        const decoder = new TextDecoder();
        let after = 0;
        for (;;) {
          const r = await getJSON('/api/console/sessions/' + sid + '/output?wait=20&after=' + after);
          after = r.next;
          const chunk = decoder.decode(Uint8Array.from(atob(r.data || ''), (ch) => ch.charCodeAt(0)), { stream: !r.closed });
          output.textContent = (output.textContent + chunk).slice(-262144);
          output.scrollTop = output.scrollHeight;
          if (r.closed) { status.textContent = 'Session ended: ' + r.closed; break; }
        }
      } catch (e) { status.textContent = e.message; }
      finally {
        if (sid) await api('/api/console/sessions/' + sid, { method: 'DELETE' }).catch(() => {});
        sid = null; run.disabled = !allowed; reply.hidden = stop.hidden = true;
      }
    };
    box.append(form, status, output, reply, stop);
  }
  for (const [selector, names] of Object.entries(places)) {
    const parent = document.querySelector(selector);
    if (!parent) continue;
    const box = node('details', { class: 'card' }, node('summary', {}, 'Host operations'));
    parent.append(box);
    let loaded = false;
    box.ontoggle = async () => {
      if (!box.open || loaded) return;
      loaded = true;
      try { await mount(box, names.split(' ')); }
      catch (e) { loaded = false; notify(e.message, 'error'); }
    };
  }
})();
