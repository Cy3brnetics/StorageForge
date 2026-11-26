'use strict';
/* The fields of one plan step as form controls, shared by the Changes forms (changes.js openTask) and the Workloads wizard (workloadwiz.js).
   stepFields(spec, values, {type, host, preset, pickPath, vmSpecs, choices}) -> {nodes, read, controls}: nodes are the labelled inputs in the order
   of spec.fields (choices {field: [{value, label}]} turns a text field into a select of those, as the wizard does for what a Proxmox node holds),
   read() gives the params as the server's check expects them, controls maps a field name to its input. Needs ui.js (el, text). */

function stepFields(spec, values, { type = '', host = '', preset = {}, pickPath = null, vmSpecs = null, choices = {} } = {}) {
  const inputs = {};
  const controls = {};
  const nodes = spec.fields.map((f) => {
    const v = values[f.name] ?? f.default ?? '';
    let input;
    if (f.kind === 'bool') {
      input = el('input', { type: 'checkbox' }); input.checked = !!v;
      inputs[f.name] = () => input.checked;
      return el('label', { class: 'check' }, input, f.label);
    }
    if (vmSpecs && f.name === 'spec') {
      input = el('select', {}, new Option('(none)', ''), ...vmSpecs.map((x) => new Option(x.note ? `${x.name}: ${x.note}` : x.name, x.name))); input.value = v || '';
    } else if (choices[f.name] && f.kind !== 'choice') {
      input = el('select', {}, new Option(f.required ? '(choose)' : '(none)', ''), ...choices[f.name].map((o) => new Option(o.label || o.value, o.value)));
      input.value = v && choices[f.name].some((o) => o.value === v) ? v : '';
      if (choices[f.name].free) {         // a list with .free also takes a name typed by hand
        const other = '\u0000other', typed = el('input', { type: 'text', class: 'mono', hidden: true, autocomplete: 'off', spellcheck: 'false', 'aria-label': f.label });
        input.append(new Option(choices[f.name].free, other));
        if (v && !input.value) { input.value = other; typed.value = v; typed.hidden = false; }
        input.addEventListener('change', () => { typed.hidden = input.value !== other; if (!typed.hidden) typed.focus(); });
        controls[f.name] = input;
        inputs[f.name] = () => (input.value === other ? typed.value.trim() : input.value);
        return el('label', { class: 'field col' }, el('span', {}, f.label + (f.required ? '' : ' (optional)')), input, typed);
      }
    } else if (f.kind === 'choice') {
      input = el('select', {}, ...f.options.map((o) => new Option(o || '(none)', o))); input.value = v || f.options[0];
    } else {
      const defPh = f.kind === 'confirm' ? (preset[spec.confirm_of || 'device'] || preset.device || preset.disk || preset.partition || preset.path || 'e.g. /dev/sdc') : '';
      input = el('input', { type: 'text', class: ['path', 'device', 'devices', 'dataset', 'zfs-snapshot', 'name', 'size', 'host', 'spec', 'options', 'confirm', 'vmname', 'url', 'sha', 'sizes', 'pubkey', 'names'].includes(f.kind) ? 'mono' : '',
                            placeholder: f.placeholder || defPh, autocomplete: 'off', spellcheck: 'false' });
      input.value = v;
    }
    controls[f.name] = input;
    inputs[f.name] = () => input.value.trim();
    if (type === 'archive' && f.kind === 'path') {
      const destination = f.name === 'dest';
      const browse = el('button', { type: 'button', class: 'btn sm', onclick: async () => {
        const current = input.value.trim();
        const slash = current.lastIndexOf('/');
        const chosen = await pickPath(host, current.slice(0, Math.max(0, slash)) || '/', {
          title: destination ? 'Choose the archive folder' : 'Choose a file or folder',
          pick: destination ? 'folder' : 'any'
        });
        if (!chosen) return;
        input.value = destination ? chosen.replace(/\/+$/, '') + '/' + current.slice(slash + 1) : chosen;
        input.dispatchEvent(new Event('input', { bubbles: true }));
        input.focus();
      } }, destination ? 'Choose folder…' : 'Browse…');
      return el('div', { class: 'field col' }, el('label', {}, f.label, input), browse);
    }
    return el('label', { class: 'field col' }, el('span', {}, f.label + (f.required ? '' : ' (optional)')), input);
  });
  if (type === 'archive') {
    const { path, dest, codec } = controls;
    const suggested = () => path.value.trim() && path.value.trim().replace(/\/+$/, '') +
      ({ 'xz-extreme': '.tar.xz', '7z-ultra': '.7z' }[codec.value] || '.tar.zst');
    let previous = suggested();
    const refresh = () => {
      const next = suggested();
      if (!dest.value || dest.value === previous) dest.value = next;
      previous = next;
    };
    path.addEventListener('input', refresh);
    codec.addEventListener('change', refresh);
    refresh();
  }
  return { nodes, read: () => Object.fromEntries(Object.entries(inputs).map(([k, f]) => [k, f()])), controls };
}
