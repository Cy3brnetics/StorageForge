/* StorageForge Security & Ransomware Defense UI
 * Handles SOC Command Center, WORM & Snapshots, Canaries & VSS, MAC & Identity, Firewall & Quarantine,
 * Behavioral eBPF & Entropy, Host Integrity (AIDE/Lynis), Malware/YARA, and Compliance & Init Wizards.
 */
let SEC_POSTURE = null;

function escapeHTML(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

async function loadSecurity(subpanel) {
  const panel = $('#tab-security');
  if (!panel) return;
  const host = S.host || '';
  try {
    const data = await getJSON(`/api/security/posture${host ? '?host=' + encodeURIComponent(host) : ''}`);
    SEC_POSTURE = data;
    renderSecurityHeader(data);
    renderSecurityNav(subpanel || 'soc');
  } catch (err) {
    panel.innerHTML = `<div class="st-failed p-4">${escapeHTML(err.message)}</div>`;
  }
}

function renderSecurityHeader(p) {
  const banner = $('#sec-header-banner');
  if (!banner) return;
  banner.className = `sec-banner sec-${p.state}`;
  const icon = p.state === 'critical' ? '🔴' : p.state === 'warning' ? '🟡' : '🟢';
  banner.innerHTML = `
    <span class="sec-banner-icon">${icon}</span>
    <span class="sec-banner-text"><b>${p.state.toUpperCase()}:</b> ${escapeHTML(p.banner)}</span>
    <div class="sec-banner-quick row">
      <button class="btn sm danger" onclick="triggerEmergencyBrakePrompt()">⚠️ Emergency Brake</button>
      <button class="btn sm" onclick="triggerAirgapPrompt(${p.airgap_active ? 'false' : 'true'})">${p.airgap_active ? 'Disarm Airgap' : '🔒 Engage Airgap'}</button>
    </div>
  `;
}

function renderSecurityNav(active) {
  const container = $('#sec-subpanel-content');
  if (!container) return;
  document.querySelectorAll('#sec-subnav button').forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.sub === active);
  });
  if (active === 'soc') renderSecSOC(container);
  else if (active === 'worm') renderSecWorm(container);
  else if (active === 'canaries') renderSecCanaries(container);
  else if (active === 'mac') renderSecMAC(container);
  else if (active === 'firewall') renderSecFirewall(container);
  else if (active === 'ebpf') renderSecEBPF(container);
  else if (active === 'integrity') renderSecIntegrity(container);
  else if (active === 'compliance') renderSecCompliance(container);
}

// ── SOC Center ───────────────────────────────────────────────────────────────
async function renderSecSOC(el) {
  const p = SEC_POSTURE || {};
  let blast = {};
  try {
    blast = await getJSON(`/api/security/incident/blast-radius${S.host ? '?host=' + encodeURIComponent(S.host) : ''}`);
  } catch {}
  el.innerHTML = `
    <div class="sec-grid">
      <div class="card sec-card">
        <h3>Threat Telemetry & Posture</h3>
        <div class="stat-row">
          <div><small>Canaries Deployed</small><b>${p.armed_canaries || 0} armed</b></div>
          <div><small>VSS Shadow Traps</small><b>${p.vss_traps || 0} active</b></div>
          <div><small>WORM Snapshots</small><b>${p.active_worm_holds || 0} locked</b></div>
          <div><small>Quarantine Pool</small><b>${p.quarantined_ips || 0} banned</b></div>
        </div>
        <p class="muted small mt-2">Clock Guard: <b>${escapeHTML(p.clock_guard?.label || 'Normal')}</b> · Quorum: <b>${escapeHTML(p.quorum?.label || 'Active')}</b></p>
      </div>

      <div class="card sec-card">
        <h3>Forensics & Blast-Radius (Live)</h3>
        <div class="stat-row">
          <div><small>Clean Data</small><b class="st-ok">${blast.clean_pct || 100}%</b></div>
          <div><small>Corrupted Files</small><b class="${blast.corrupted_files ? 'st-failed' : ''}">${blast.corrupted_files || 0}</b></div>
          <div><small>RPO Loss Metric</small><b>${blast.rpo_seconds || 0}s</b></div>
        </div>
        <div class="row mt-3">
          <button class="btn sm pri" onclick="stageCleanRoomPrompt('${blast.incident_snapshot || ''}')">🧪 Mount Clean-Room Sandbox</button>
          <button class="btn sm" onclick="triggerComplianceInitPrompt('cis-l2')">📋 Init Compliance</button>
        </div>
      </div>
    </div>

    <div class="card sec-card mt-3">
      <h3>Unified Threat Timeline & Incident Stream</h3>
      ${p.timeline && p.timeline.length ? `
        <table class="tbl mt-2">
          <thead><tr><th>Time</th><th>Severity</th><th>Host</th><th>Event Description</th><th>Status</th></tr></thead>
          <tbody>
            ${p.timeline.map((e) => `
              <tr>
                <td><small>${new Date(e.timestamp * 1000).toLocaleTimeString()}</small></td>
                <td><span class="pill ${e.severity === 'critical' ? 'danger' : e.severity === 'warning' ? 'warning' : 'ok'}">${e.severity.toUpperCase()}</span></td>
                <td><b>${escapeHTML(e.host)}</b></td>
                <td>${escapeHTML(e.description)}</td>
                <td><span class="muted">${escapeHTML(e.status)}</span></td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      ` : '<p class="muted">No critical incidents or alarms recorded in current buffer.</p>'}
    </div>
  `;
}

// ── WORM Retention ───────────────────────────────────────────────────────────
async function renderSecWorm(el) {
  el.innerHTML = '<p class="muted">Loading WORM retention holds and quorum status…</p>';
  try {
    const data = await getJSON(`/api/security/worm/holds${S.host ? '?host=' + encodeURIComponent(S.host) : ''}`);
    el.innerHTML = `
      <div class="row wrap between items-center mb-3">
        <div>
          <h3>WORM Retention & Snapshot Vault</h3>
          <span class="muted small">${data.summary.active_holds} active holds · ${data.summary.expiring_24h} expiring <24h · ${data.summary.legal_holds} legal holds</span>
        </div>
        <button class="btn sm pri" onclick="applyWormHoldPrompt()">+ Apply WORM Hold</button>
      </div>

      ${data.pending_timelocks && data.pending_timelocks.length ? `
        <div class="card sec-card warning mb-3">
          <h4>⏳ Pending Timelock Releases (${data.quorum.label})</h4>
          ${data.pending_timelocks.map((t) => `
            <div class="row between items-center mt-2 p-2 border-b">
              <div>
                <b>${escapeHTML(t.target_ref)}</b> on <i>${escapeHTML(t.host)}</i> requested by ${escapeHTML(t.actor)}<br>
                <small class="muted">Executes in ${Math.round(t.remaining_seconds / 3600)}h (${new Date(t.executes_at * 1000).toLocaleString()})</small>
              </div>
              <div class="row gap-2">
                <button class="btn sm danger" onclick="abortTimelock(${t.id})">🛑 Abort & Revoke</button>
                ${data.quorum.multi_admin ? `<button class="btn sm pri" onclick="approveQuorum(${t.id})">✍️ Approve Quorum</button>` : ''}
                <button class="btn sm" onclick="breakGlassPrompt(${t.id})">🔑 Offline Break-Glass Key</button>
              </div>
            </div>
          `).join('')}
        </div>
      ` : ''}

      <table class="tbl">
        <thead><tr><th>Snapshot</th><th>Dataset</th><th>Hold Tag</th><th>Created</th><th>Expires</th><th>Status</th><th>Actions</th></tr></thead>
        <tbody>
          ${data.holds.map((h) => `
            <tr>
              <td><b>${escapeHTML(h.snapshot)}</b></td>
              <td>${escapeHTML(h.dataset)}</td>
              <td><code>${escapeHTML(h.hold_tag)}</code></td>
              <td>${new Date(h.created_at * 1000).toLocaleDateString()}</td>
              <td>${h.legal_hold ? '📌 Permanent Legal Hold' : h.expires_at ? new Date(h.expires_at * 1000).toLocaleDateString() : '—'}</td>
              <td><span class="pill ${h.status === 'locked' ? 'ok' : 'warning'}">${h.status}</span></td>
              <td>
                ${h.status === 'locked' ? `<button class="btn sm ghost" onclick="requestHoldRelease(${h.id}, '${escapeHTML(h.snapshot)}')">Request Release</button>` : '—'}
              </td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    `;
  } catch (err) { el.innerHTML = `<p class="st-failed">${escapeHTML(err.message)}</p>`; }
}

// ── Canaries & Tripwires ─────────────────────────────────────────────────────
async function renderSecCanaries(el) {
  el.innerHTML = '<p class="muted">Loading canaries and VSS shadow trap status…</p>';
  try {
    const data = await getJSON(`/api/security/canaries${S.host ? '?host=' + encodeURIComponent(S.host) : ''}`);
    el.innerHTML = `
      <div class="row wrap between items-center mb-3">
        <div>
          <h3>Canaries & VSS Shadow Decoy Console</h3>
          <span class="muted small">${data.summary.total_canaries} canaries · ${data.summary.vss_traps} VSS shadow interceptors · Tripwire state: <b>${data.summary.tripwire_state}</b></span>
        </div>
        <div class="row gap-2">
          <button class="btn sm" onclick="testCanariesPrompt()">🧪 Simulate Canary Trip</button>
          <button class="btn sm pri" onclick="deployCanariesPrompt()">+ Deploy Canaries</button>
        </div>
      </div>

      <table class="tbl">
        <thead><tr><th>Decoy Path / Trap</th><th>Target Share</th><th>Trap Type</th><th>Baseline Hash</th><th>Status</th></tr></thead>
        <tbody>
          ${data.canaries.map((c) => `
            <tr>
              <td><b>${escapeHTML(c.file_name)}</b></td>
              <td>${escapeHTML(c.share_path)}</td>
              <td><span class="pill sm">${c.trap_type}</span></td>
              <td><code>${c.baseline_sha256.slice(0, 16)}…</code></td>
              <td><span class="pill ${c.status === 'armed' ? 'ok' : 'danger'}">${c.status.toUpperCase()}</span></td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    `;
  } catch (err) { el.innerHTML = `<p class="st-failed">${escapeHTML(err.message)}</p>`; }
}

// ── Mandatory Access Control (MAC) ───────────────────────────────────────────
async function renderSecMAC(el) {
  el.innerHTML = '<p class="muted">Loading Mandatory Access Control and AVC audit logs…</p>';
  try {
    const data = await getJSON(`/api/security/mac/status${S.host ? '?host=' + encodeURIComponent(S.host) : ''}`);
    const avc = await getJSON(`/api/security/mac/avc${S.host ? '?host=' + encodeURIComponent(S.host) : ''}`);
    el.innerHTML = `
      <div class="row wrap between items-center mb-3">
        <div>
          <h3>Mandatory Access Control (MAC) Hub</h3>
          <span class="muted small">Framework: <b>${data.framework}</b> · Mode: <b>${data.mode}</b> · Drift: ${data.drift_count}</span>
        </div>
      </div>

      <h4>Storage Booleans</h4>
      <table class="tbl mb-3">
        <thead><tr><th>Boolean</th><th>State</th><th>Expected</th><th>Description</th></tr></thead>
        <tbody>
          ${data.booleans.map((b) => `
            <tr>
              <td><code>${escapeHTML(b.name)}</code></td>
              <td><b>${b.current}</b></td>
              <td>${b.expected}</td>
              <td class="muted">${escapeHTML(b.description)}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>

      <h4>Recent Storage AVC Denials</h4>
      ${avc.events && avc.events.length ? `
        <table class="tbl">
          <thead><tr><th>Time</th><th>Daemon</th><th>Target Path</th><th>Context</th><th>Action</th></tr></thead>
          <tbody>
            ${avc.events.map((e) => `
              <tr>
                <td><small>${new Date(e.timestamp * 1000).toLocaleTimeString()}</small></td>
                <td><b>${escapeHTML(e.daemon)}</b></td>
                <td><code>${escapeHTML(e.target_path)}</code></td>
                <td>${escapeHTML(e.tcontext)}</td>
                <td><button class="btn sm" onclick="remediateMACPrompt(${e.id}, '${escapeHTML(e.target_path)}')">Doctor Remediate</button></td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      ` : '<p class="muted">No storage-related AVC denials recorded.</p>'}
    `;
  } catch (err) { el.innerHTML = `<p class="st-failed">${escapeHTML(err.message)}</p>`; }
}

// ── Storage Firewall & Quarantine ────────────────────────────────────────────
async function renderSecFirewall(el) {
  el.innerHTML = '<p class="muted">Loading storage firewall and active attacker quarantine pool…</p>';
  try {
    const data = await getJSON(`/api/security/firewall/quarantine${S.host ? '?host=' + encodeURIComponent(S.host) : ''}`);
    el.innerHTML = `
      <div class="row wrap between items-center mb-3">
        <div>
          <h3>Storage Firewall & Network Fencing</h3>
          <span class="muted small">Backend: <b>${data.backend}</b> · Host Airgap: <b>${data.airgap_active ? 'ACTIVE' : 'NORMAL'}</b></span>
        </div>
        <button class="btn sm pri" onclick="quarantineIPPrompt()">+ Quarantine IP</button>
      </div>

      <h4>Active Attacker Quarantine Pool (sf_quarantine)</h4>
      ${data.quarantine && data.quarantine.length ? `
        <table class="tbl mb-3">
          <thead><tr><th>IP Address</th><th>Reason</th><th>Banned At</th><th>Expires</th><th>Action</th></tr></thead>
          <tbody>
            ${data.quarantine.map((q) => `
              <tr>
                <td><b><code>${escapeHTML(q.ip_address)}</code></b></td>
                <td>${escapeHTML(q.reason)}</td>
                <td><small>${new Date(q.tripped_at * 1000).toLocaleTimeString()}</small></td>
                <td>${q.permanent ? 'Permanent Blacklist' : q.remaining_seconds ? Math.round(q.remaining_seconds / 60) + ' min' : 'Expired'}</td>
                <td><button class="btn sm danger" onclick="releaseQuarantineIP('${escapeHTML(q.ip_address)}')">Release Ban</button></td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      ` : '<p class="muted mb-3">No client IP addresses quarantined.</p>'}
    `;
  } catch (err) { el.innerHTML = `<p class="st-failed">${escapeHTML(err.message)}</p>`; }
}

// ── Behavioral eBPF & Entropy ────────────────────────────────────────────────
async function renderSecEBPF(el) {
  el.innerHTML = '<p class="muted">Loading behavioral eBPF telemetry and entropy analytics…</p>';
  try {
    const data = await getJSON(`/api/security/ebpf/events${S.host ? '?host=' + encodeURIComponent(S.host) : ''}`);
    el.innerHTML = `
      <div class="row wrap between items-center mb-3">
        <div>
          <h3>Behavioral eBPF & Shannon Entropy Analytics</h3>
          <span class="muted small">${data.driver} · ${data.ruleset_version}</span>
        </div>
      </div>

      <div class="sec-grid mb-3">
        <div class="card sec-card">
          <h4>Scan-Diff Mutation Velocity</h4>
          <div class="stat-row">
            <div><small>Hourly Mutations</small><b>${data.velocity_files_hr} files/hr</b></div>
            <div><small>Trigger Threshold</small><b>${data.velocity_threshold} files/hr</b></div>
          </div>
          <p class="muted small mt-2">Added: ${data.velocity_breakdown.added} · Modified: ${data.velocity_breakdown.modified} · Deleted: ${data.velocity_breakdown.deleted}</p>
        </div>
        <div class="card sec-card">
          <h4>Shannon Entropy Distribution</h4>
          <div class="stat-row">
            <div><small>Plaintext (H &lt; 5.5)</small><b>${data.entropy_distribution.plaintext_pct}%</b></div>
            <div><small>Compressed (H 7.2-7.6)</small><b>${data.entropy_distribution.compressed_pct}%</b></div>
            <div><small>Ciphertext (H &gt; 7.92)</small><b class="${data.entropy_distribution.ciphertext_pct > 0 ? 'st-failed' : 'st-ok'}">${data.entropy_distribution.ciphertext_pct}%</b></div>
          </div>
        </div>
      </div>
    `;
  } catch (err) { el.innerHTML = `<p class="st-failed">${escapeHTML(err.message)}</p>`; }
}

// ── Host Integrity (AIDE & Lynis) ────────────────────────────────────────────
async function renderSecIntegrity(el) {
  el.innerHTML = '<p class="muted">Loading AIDE cryptographic FIM and Lynis CIS audit scorecard…</p>';
  try {
    const aide = await getJSON(`/api/security/integrity/aide${S.host ? '?host=' + encodeURIComponent(S.host) : ''}`);
    const lynis = await getJSON(`/api/security/integrity/lynis${S.host ? '?host=' + encodeURIComponent(S.host) : ''}`);
    el.innerHTML = `
      <div class="row wrap between items-center mb-3">
        <div>
          <h3>Host Integrity & CIS Hardening</h3>
          <span class="muted small">Lynis Score: <b>${lynis.hardening_index}/100</b> · AIDE FIM: <b>${aide.baseline_verified ? 'Verified' : 'Drift Detected'}</b></span>
        </div>
        <button class="btn sm pri" onclick="reinitAidePrompt()">Re-init AIDE Baseline</button>
      </div>

      <h4>CIS Hardening Recommendations</h4>
      <table class="tbl mb-3">
        <thead><tr><th>Severity</th><th>Category</th><th>Finding</th><th>Recommendation</th></tr></thead>
        <tbody>
          ${lynis.recommendations.map((r) => `
            <tr>
              <td><span class="pill ${r.severity === 'high' ? 'danger' : r.severity === 'medium' ? 'warning' : 'ok'}">${r.severity.toUpperCase()}</span></td>
              <td><b>${escapeHTML(r.category)}</b></td>
              <td>${escapeHTML(r.finding)}</td>
              <td>${escapeHTML(r.recommendation)}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    `;
  } catch (err) { el.innerHTML = `<p class="st-failed">${escapeHTML(err.message)}</p>`; }
}

// ── Global Compliance Standards & Init Scripts ───────────────────────────────
async function renderSecCompliance(el) {
  el.innerHTML = '<p class="muted">Loading global compliance standards…</p>';
  try {
    const stds = await getJSON('/api/security/compliance/standards');
    const status = S.host ? await getJSON(`/api/security/compliance/status/${encodeURIComponent(S.host)}`).catch(() => ({})) : {};
    el.innerHTML = `
      <div class="row wrap between items-center mb-3">
        <div>
          <h3>Global Compliance Standards & Init Script Engine</h3>
          <span class="muted small">${status.standard_name ? 'Current standard: ' + status.standard_name + ' (Score: ' + status.score + '%)' : 'Select a compliance standard to stage deployment plan'}</span>
        </div>
      </div>

      <div class="sec-grid mb-3">
        ${stds.standards.map((s) => `
          <div class="card sec-card">
            <h4>${escapeHTML(s.name)}</h4>
            <p class="muted small">Target Lynis: <b>${s.target_lynis}+</b> · WORM hold: <b>${s.min_worm_days} days</b> · umask: <b>${s.umask}</b></p>
            <ul class="muted small pl-4 mt-2">
              ${s.controls.map((c) => `<li>${escapeHTML(c)}</li>`).join('')}
            </ul>
            <div class="mt-3">
              <button class="btn sm pri" onclick="triggerComplianceInitPrompt('${s.id}')">🚀 Stage ${s.id.toUpperCase()} Init Script</button>
            </div>
          </div>
        `).join('')}
      </div>
    `;
  } catch (err) { el.innerHTML = `<p class="st-failed">${escapeHTML(err.message)}</p>`; }
}

// ── Action Prompts & Handlers ────────────────────────────────────────────────
async function triggerEmergencyBrakePrompt() {
  const ip = prompt('Target client IP to quarantine (leave empty if internal/unknown):', '');
  if (ip === null) return;
  try {
    const r = await (await postJSON('/api/security/incident/brake', {
      host: S.host || 'localhost',
      client_ip: ip.trim(),
      reason: 'Manual emergency brake trigger from SOC Header',
    })).json();
    toast(`Emergency brake executed: ${r.steps_executed.join(', ')}`);
    loadSecurity('soc');
  } catch (err) { toast(err.message); }
}

async function triggerAirgapPrompt(enable) {
  if (!confirm(`${enable ? 'Engage Emergency Airgap' : 'Disarm Airgap'} for ${S.host || 'all hosts'}?`)) return;
  try {
    await postJSON('/api/security/firewall/airgap', { host: S.host || 'localhost', enabled: enable });
    toast(`Host airgap ${enable ? 'engaged' : 'disarmed'}`);
    loadSecurity('firewall');
  } catch (err) { toast(err.message); }
}

async function applyWormHoldPrompt() {
  const ds = prompt('ZFS Dataset or Btrfs Subvolume path:', 'tank/shares');
  if (!ds) return;
  const days = prompt('Retention days (WORM lock duration):', '14');
  if (!days) return;
  try {
    await postJSON('/api/security/worm/hold', { host: S.host || 'localhost', dataset: ds.trim(), retention_days: Number(days) });
    toast('WORM retention hold applied successfully');
    loadSecurity('worm');
  } catch (err) { toast(err.message); }
}

async function requestHoldRelease(id, snap) {
  if (!confirm(`Request release of WORM hold for ${snap}? (Triggers Quorum or Timelock cool-off window)`)) return;
  try {
    const r = await (await postJSON('/api/security/worm/release', { hold_id: id })).json();
    toast(`Release requested: ${r.cooloff_hours}h cool-off buffer active`);
    loadSecurity('worm');
  } catch (err) { toast(err.message); }
}

async function abortTimelock(id) {
  if (!confirm('Abort and revoke this pending timelocked hold release immediately?')) return;
  try {
    await postJSON('/api/security/worm/abort', { timelock_id: id });
    toast('Timelock release aborted');
    loadSecurity('worm');
  } catch (err) { toast(err.message); }
}

async function approveQuorum(id) {
  try {
    await postJSON('/api/security/worm/quorum/approve', { timelock_id: id });
    toast('Quorum approved and hold released');
    loadSecurity('worm');
  } catch (err) { toast(err.message); }
}

async function breakGlassPrompt(id) {
  const key = prompt('Enter 64-character offline Break-Glass emergency key:');
  if (!key) return;
  try {
    await postJSON('/api/security/worm/break-glass', { timelock_id: id, break_glass_key: key.trim() });
    toast('Break-Glass key verified: timelock bypassed');
    loadSecurity('worm');
  } catch (err) { toast(err.message); }
}

async function deployCanariesPrompt() {
  const share = prompt('Share path to protect with canaries and VSS shadow trap:', '/srv/shares/general');
  if (!share) return;
  try {
    const r = await (await postJSON('/api/security/canaries/deploy', { host: S.host || 'localhost', shares: [share.trim()] })).json();
    toast(`Deployed ${r.count} canaries and VSS shadow traps`);
    loadSecurity('canaries');
  } catch (err) { toast(err.message); }
}

async function testCanariesPrompt() {
  try {
    await postJSON('/api/security/canaries/test', { host: S.host || 'localhost', simulate_trip: false });
    toast('Non-destructive canary tripwire verification succeeded');
  } catch (err) { toast(err.message); }
}

async function quarantineIPPrompt() {
  const ip = prompt('IP address or CIDR to quarantine:');
  if (!ip) return;
  const reason = prompt('Reason for quarantine:', 'Manual administrative block');
  try {
    await postJSON('/api/security/firewall/quarantine', { host: S.host || 'localhost', ip_address: ip.trim(), reason: reason || '' });
    toast(`IP ${ip} quarantined in sf_quarantine set`);
    loadSecurity('firewall');
  } catch (err) { toast(err.message); }
}

async function releaseQuarantineIP(ip) {
  if (!confirm(`Release ${ip} from quarantine?`)) return;
  try {
    await api(`/api/security/firewall/quarantine/${encodeURIComponent(ip)}${S.host ? '?host=' + encodeURIComponent(S.host) : ''}`, { method: 'DELETE' });
    toast(`IP ${ip} released from quarantine`);
    loadSecurity('firewall');
  } catch (err) { toast(err.message); }
}

async function remediateMACPrompt(avcId, targetPath) {
  try {
    const r = await (await postJSON('/api/security/mac/remediate', { host: S.host || 'localhost', avc_id: avcId, target_path: targetPath })).json();
    toast('Doctor remediation plan generated and executed');
    loadSecurity('mac');
  } catch (err) { toast(err.message); }
}

async function reinitAidePrompt() {
  if (!confirm('Re-initialize AIDE cryptographic file integrity baseline?')) return;
  try {
    await postJSON('/api/security/integrity/aide/init', { host: S.host || 'localhost' });
    toast('AIDE cryptographic baseline initialized');
    loadSecurity('integrity');
  } catch (err) { toast(err.message); }
}

async function stageCleanRoomPrompt(snapshot) {
  const snap = prompt('Snapshot to mount in isolated Clean-Room sandbox:', snapshot || 'tank/shares@ransomware-incident');
  if (!snap) return;
  try {
    const r = await (await postJSON('/api/security/incident/clean-room', { host: S.host || 'localhost', snapshot: snap.trim() })).json();
    toast(`Clean-room sandbox mounted at ${r.sandbox_mount}`);
  } catch (err) { toast(err.message); }
}

async function triggerComplianceInitPrompt(profile) {
  try {
    const r = await (await postJSON('/api/security/compliance/init', { host: S.host || 'localhost', profile })).json();
    toast(`Compliance baseline staged: ${r.standard_name}`);
    loadSecurity('compliance');
  } catch (err) { toast(err.message); }
}
