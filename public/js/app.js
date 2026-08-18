/**
 * DashSec VPS Cyber Defense & Live SOC Dashboard
 * Real-Time WebSocket, Telemetry, Firewall & Threat Management
 */

class DashSecApp {
  constructor() {
    this.ws = null;
    this.audioContext = null;
    this.soundEnabled = true;
    this.activeFilter = 'ALL';
    this.threats = [];
    this.stats = {};
    this.system = {};
    this.timelineChart = null;
    this.vectorsChart = null;

    this.initUI();
    this.initWebSocket();
    this.initAudio();
    this.loadInitialData();
  }

  // Helper to construct API URL based on current access path
  getApiUrl(endpoint) {
    const cleanEndpoint = endpoint.startsWith('/') ? endpoint : '/' + endpoint;
    const pathname = window.location.pathname;
    if (pathname.includes('/dashsec')) {
      return `/dashsec${cleanEndpoint}`;
    }
    return cleanEndpoint;
  }

  // --- UI INITIALIZATION & EVENT HANDLERS ---
  initUI() {
    // 1. Tab Switching
    document.querySelectorAll('.tab-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

        btn.classList.add('active');
        const targetTab = document.getElementById(btn.dataset.tab);
        if (targetTab) targetTab.classList.add('active');

        // Refresh specific tab data
        if (btn.dataset.tab === 'tab-blocked-ips') this.loadBlockedIPs();
        if (btn.dataset.tab === 'tab-whitelist') this.loadWhitelist();
        if (btn.dataset.tab === 'tab-smtp') this.loadSMTPSettings();
        if (btn.dataset.tab === 'tab-analytics') this.updateCharts();
      });
    });

    // 2. Sound Toggle
    const soundBtn = document.getElementById('btn-sound-toggle');
    if (soundBtn) {
      soundBtn.addEventListener('click', () => {
        this.soundEnabled = !this.soundEnabled;
        document.getElementById('sound-icon').textContent = this.soundEnabled ? '🔊' : '🔇';
        document.getElementById('sound-text').textContent = this.soundEnabled ? 'Sound ON' : 'Sound OFF';
        this.showToast(this.soundEnabled ? 'Audio Alert Diaktifkan' : 'Audio Alert Dimatikan');
      });
    }

    // 3. Filter Chips
    document.querySelectorAll('.filter-chip').forEach(chip => {
      chip.addEventListener('click', () => {
        document.querySelectorAll('.filter-chip').forEach(c => c.classList.remove('active'));
        chip.classList.add('active');
        this.activeFilter = chip.dataset.filter;
        this.renderThreatTable();
      });
    });

    // 4. Threat Search Input
    const searchInput = document.getElementById('threat-search-input');
    if (searchInput) {
      searchInput.addEventListener('input', () => this.renderThreatTable());
    }

    // 5. Modals Open/Close
    document.querySelectorAll('[data-close]').forEach(el => {
      el.addEventListener('click', () => {
        const modal = document.getElementById(el.dataset.close);
        if (modal) modal.classList.remove('open');
      });
    });

    document.getElementById('btn-manual-ban')?.addEventListener('click', () => {
      document.getElementById('modal-manual-ban')?.classList.add('open');
    });

    document.getElementById('btn-add-whitelist')?.addEventListener('click', () => {
      document.getElementById('modal-add-whitelist')?.classList.add('open');
    });

    document.getElementById('btn-open-simulator')?.addEventListener('click', () => {
      document.getElementById('modal-simulator')?.classList.add('open');
    });

    document.getElementById('btn-open-smtp')?.addEventListener('click', () => {
      document.getElementById('tab-btn-smtp-tab')?.click();
    });

    // 6. Manual Ban Form Submit
    document.getElementById('form-manual-ban')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const ip = document.getElementById('ban-ip').value.trim();
      const reason = document.getElementById('ban-reason').value.trim();
      const duration_hours = parseInt(document.getElementById('ban-duration').value, 10);
      const threat_score = parseInt(document.getElementById('ban-threat-score').value, 10);

      try {
        const res = await fetch(this.getApiUrl('/api/blocked'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ip, reason, duration_hours, threat_score })
        });
        const json = await res.json();
        if (json.success) {
          this.showToast(`IP ${ip} berhasil diblokir ke firewall!`);
          document.getElementById('modal-manual-ban').classList.remove('open');
          document.getElementById('form-manual-ban').reset();
          this.loadBlockedIPs();
          this.loadStats();
        } else {
          alert(json.reason || json.error || 'Gagal memblokir IP');
        }
      } catch (err) {
        alert('Error: ' + err.message);
      }
    });

    // 7. Flush Firewall Button
    document.getElementById('btn-flush-firewall')?.addEventListener('click', async () => {
      if (confirm('Yakin ingin membersihkan semua aturan blokir firewall DASHSEC_IPS?')) {
        try {
          const res = await fetch(this.getApiUrl('/api/firewall/flush'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
          });
          const json = await res.json();
          this.showToast('Semua aturan blokir firewall telah dibersihkan');
          this.loadBlockedIPs();
          this.loadStats();
        } catch (e) {
          alert('Error: ' + e.message);
        }
      }
    });

    // 8. Add Whitelist Form
    document.getElementById('form-add-whitelist')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const ip = document.getElementById('wl-ip').value.trim();
      const note = document.getElementById('wl-note').value.trim();

      try {
        const res = await fetch(this.getApiUrl('/api/whitelist'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ip, note })
        });
        const json = await res.json();
        if (json.success) {
          this.showToast(`IP ${ip} berhasil ditambahkan ke whitelist`);
          document.getElementById('modal-add-whitelist').classList.remove('open');
          document.getElementById('form-add-whitelist').reset();
          this.loadWhitelist();
        }
      } catch (err) {
        alert('Error: ' + err.message);
      }
    });

    // 9. SMTP Config Form
    document.getElementById('smtp-config-form')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const host = document.getElementById('smtp-host').value.trim();
      const port = document.getElementById('smtp-port').value.trim();
      const auth_user = document.getElementById('smtp-user').value.trim();
      const auth_pass = document.getElementById('smtp-pass').value;
      const sender_email = document.getElementById('smtp-sender-email').value.trim();
      const sender_name = document.getElementById('smtp-sender-name').value.trim();
      const recipient_email = document.getElementById('smtp-recipient').value.trim();
      const notify_on_breach = document.getElementById('smtp-notify-breach').checked;
      const notify_on_block = document.getElementById('smtp-notify-block').checked;

      const saveStatus = document.getElementById('smtp-save-status');
      saveStatus.textContent = 'Menyimpan...';

      try {
        const res = await fetch(this.getApiUrl('/api/smtp'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ host, port, auth_user, auth_pass, sender_email, sender_name, recipient_email, notify_on_breach, notify_on_block })
        });
        const json = await res.json();
        if (json.success) {
          saveStatus.textContent = '✅ Tersimpan!';
          this.showToast('Pengaturan SMTP berhasil diperbarui!');
          setTimeout(() => { saveStatus.textContent = ''; }, 3000);
        }
      } catch (err) {
        saveStatus.textContent = '❌ Gagal';
        alert('Gagal menyimpan SMTP: ' + err.message);
      }
    });

    // 10. Test SMTP Email Button
    document.getElementById('btn-test-smtp-mail')?.addEventListener('click', async () => {
      const btn = document.getElementById('btn-test-smtp-mail');
      btn.disabled = true;
      btn.innerHTML = '<span>⏳</span> Mengirim Test Alert...';

      try {
        const res = await fetch(this.getApiUrl('/api/smtp/test'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({})
        });
        const json = await res.json();
        if (json.success) {
          this.showToast('✅ ' + json.message);
          this.loadAlertLogs();
        } else {
          alert('Gagal mengirim email test: ' + (json.error || 'Unknown error'));
        }
      } catch (err) {
        alert('Error: ' + err.message);
      } finally {
        btn.disabled = false;
        btn.innerHTML = '<span>✉️</span> Uji Coba Kirim Email (Test Alert)';
      }
    });

    // 11. Simulator Action Buttons
    document.querySelectorAll('.btn-run-sim').forEach(btn => {
      btn.addEventListener('click', async () => {
        const simType = btn.dataset.sim;
        const resultBox = document.getElementById('sim-result-box');
        const resultContent = document.getElementById('sim-result-content');
        
        resultBox.style.display = 'block';
        resultContent.innerHTML = '<em>⚡ Menjalankan simulasi payload serangan...</em>';

        try {
          const res = await fetch(this.getApiUrl('/api/simulate'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ type: simType })
          });
          const json = await res.json();
          if (json.success) {
            resultContent.innerHTML = `✅ <strong>Sukses:</strong> ${json.message}`;
            this.showToast(json.message, simType === 'BREACH_ALERT' ? 'danger' : 'success');
            if (simType === 'BREACH_ALERT') {
              this.playCyberAlertSound(true);
            }
            this.loadStats();
          } else {
            resultContent.innerHTML = `❌ <strong>Gagal:</strong> ${json.error}`;
          }
        } catch (err) {
          resultContent.innerHTML = `❌ <strong>Error:</strong> ${err.message}`;
        }
      });
    });
  }

  // --- WEBAUDIO ALERT SOUND GENERATOR ---
  initAudio() {
    try {
      window.AudioContext = window.AudioContext || window.webkitAudioContext;
      this.audioContext = new AudioContext();
    } catch (e) {}
  }

  playCyberAlertSound(isCritical = false) {
    if (!this.soundEnabled || !this.audioContext) return;
    try {
      if (this.audioContext.state === 'suspended') {
        this.audioContext.resume();
      }

      const osc = this.audioContext.createOscillator();
      const gain = this.audioContext.createGain();

      osc.type = isCritical ? 'sawtooth' : 'sine';
      osc.frequency.setValueAtTime(isCritical ? 880 : 520, this.audioContext.currentTime);

      if (isCritical) {
        osc.frequency.exponentialRampToValueAtTime(320, this.audioContext.currentTime + 0.3);
      } else {
        osc.frequency.exponentialRampToValueAtTime(780, this.audioContext.currentTime + 0.15);
      }

      gain.gain.setValueAtTime(0.2, this.audioContext.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.01, this.audioContext.currentTime + (isCritical ? 0.35 : 0.2));

      osc.connect(gain);
      gain.connect(this.audioContext.destination);

      osc.start();
      osc.stop(this.audioContext.currentTime + (isCritical ? 0.35 : 0.2));
    } catch (e) {}
  }

  // --- WEBSOCKET ENGINE ---
  initWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const isDashsecSubpath = window.location.pathname.includes('/dashsec');
    const wsPath = isDashsecSubpath ? '/dashsec/ws' : '/ws';
    const wsUrl = `${protocol}//${window.location.host}${wsPath}`;

    try {
      this.ws = new WebSocket(wsUrl);
    } catch (e) {
      console.warn('[WS] Error initializing websocket:', e.message);
      return;
    }

    this.ws.onopen = () => {
      console.log('[WS] Connected to DashSec Live Stream');
      const statusEl = document.getElementById('socket-connection-status');
      if (statusEl) {
        statusEl.className = 'connected';
        statusEl.textContent = '● Connected (WebSocket Live)';
      }
    };

    this.ws.onclose = () => {
      const statusEl = document.getElementById('socket-connection-status');
      if (statusEl) {
        statusEl.className = '';
        statusEl.textContent = '○ Reconnecting...';
      }
      setTimeout(() => this.initWebSocket(), 3000);
    };

    this.ws.onerror = (err) => {
      console.error('[WS] Socket error');
    };

    this.ws.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data);
        this.handleWsEvent(msg.event, msg.data);
      } catch (err) {
        console.error('[WS] Parse error:', err);
      }
    };
  }

  handleWsEvent(event, data) {
    if (event === 'INIT') {
      this.stats = data.stats || {};
      this.system = data.system || {};
      this.threats = data.recentThreats || [];
      this.updateKPICards();
      this.updateSystemTelemetry();
      this.renderThreatTable();
      this.initCharts();
    } else if (event === 'THREAT_DETECTED') {
      this.threats.unshift(data);
      if (this.threats.length > 200) this.threats.pop();

      const isBreach = data.status === 'BREACHED';
      this.playCyberAlertSound(isBreach);

      this.showToast(
        `${isBreach ? '🚨 BREACH' : '🛡️ BLOCKED'}: ${data.attack_type} dari ${data.source_ip}`,
        isBreach ? 'danger' : 'default'
      );

      this.updateKPICards();
      this.renderThreatTable(true);
      this.updateCharts();
    } else if (event === 'IP_BLOCKED') {
      this.loadBlockedIPs();
      this.loadStats();
    } else if (event === 'SYSTEM_TICK') {
      if (data.system) {
        this.system = data.system;
        this.updateSystemTelemetry();
      }
      if (data.threatStats) {
        this.stats = data.threatStats;
        this.updateKPICards();
      }
    }
  }

  // --- DATA FETCHING ---
  async loadInitialData() {
    await this.loadStats();
    await this.loadThreats();
  }

  async loadStats() {
    try {
      const res = await fetch(this.getApiUrl('/api/stats'));
      const json = await res.json();
      if (json.success) {
        this.stats = json.stats;
        this.system = json.system;
        this.updateKPICards();
        this.updateSystemTelemetry();
        this.updateCharts();
      }
    } catch (e) {}
  }

  async loadThreats() {
    try {
      const res = await fetch(this.getApiUrl('/api/threats?limit=60'));
      const json = await res.json();
      if (json.success) {
        this.threats = json.data;
        this.renderThreatTable();
      }
    } catch (e) {}
  }

  async loadBlockedIPs() {
    try {
      const res = await fetch(this.getApiUrl('/api/blocked'));
      const json = await res.json();
      if (json.success) {
        this.renderBlockedTable(json.data);
      }
    } catch (e) {}
  }

  async loadWhitelist() {
    try {
      const res = await fetch(this.getApiUrl('/api/whitelist'));
      const json = await res.json();
      if (json.success) {
        this.renderWhitelistTable(json.data);
      }
    } catch (e) {}
  }

  async loadSMTPSettings() {
    try {
      const res = await fetch(this.getApiUrl('/api/smtp'));
      const json = await res.json();
      if (json.success && json.data) {
        const s = json.data;
        document.getElementById('smtp-host').value = s.host || '';
        document.getElementById('smtp-port').value = s.port || 587;
        document.getElementById('smtp-user').value = s.auth_user || '';
        document.getElementById('smtp-pass').value = s.auth_pass || '';
        document.getElementById('smtp-sender-email').value = s.sender_email || '';
        document.getElementById('smtp-sender-name').value = s.sender_name || '';
        document.getElementById('smtp-recipient').value = s.recipient_email || 'mrhxxx7@gmail.com';
        document.getElementById('smtp-notify-breach').checked = Boolean(s.notify_on_breach);
        document.getElementById('smtp-notify-block').checked = Boolean(s.notify_on_block);
      }
      this.loadAlertLogs();
    } catch (e) {}
  }

  async loadAlertLogs() {
    try {
      const res = await fetch(this.getApiUrl('/api/alerts'));
      const json = await res.json();
      if (json.success) {
        this.renderAlertLogs(json.data);
      }
    } catch (e) {}
  }

  // --- RENDERING VIEWS ---
  updateKPICards() {
    const s = this.stats || {};
    const totalAttacks = s.totalAttacks || 0;
    const totalBlocked = s.totalBlocked || 0;
    const totalBreached = s.totalBreached || 0;
    const activeBlocks = s.activeBlocks || 0;
    const todayAttacks = s.todayAttacks || 0;
    const todayBreached = s.todayBreached || 0;

    document.getElementById('val-total-attacks').textContent = totalAttacks.toLocaleString();
    document.getElementById('val-today-attacks').textContent = `+${todayAttacks} Hari Ini`;

    document.getElementById('val-active-blocks').textContent = activeBlocks.toLocaleString();
    const rate = totalAttacks > 0 ? Math.round((totalBlocked / totalAttacks) * 100) : 100;
    document.getElementById('val-blocked-rate').textContent = `${rate}% Mitigated`;

    document.getElementById('val-total-breaches').textContent = totalBreached.toLocaleString();
    document.getElementById('val-breach-status').textContent = `${todayBreached} Insiden Kritis`;

    // DEFCON status badge
    const defconBadge = document.getElementById('defcon-badge');
    const defconStatus = document.getElementById('defcon-status');
    if (totalBreached > 0 || todayBreached > 0) {
      defconBadge.className = 'defcon-badge defcon-red';
      defconBadge.querySelector('.defcon-title').textContent = 'DEFCON 1';
      defconStatus.textContent = 'HIGH ALERT';
    } else if (todayAttacks > 50) {
      defconBadge.className = 'defcon-badge defcon-green';
      defconBadge.querySelector('.defcon-title').textContent = 'DEFCON 3';
      defconStatus.textContent = 'ACTIVE ATTACK';
    } else {
      defconBadge.className = 'defcon-badge defcon-green';
      defconBadge.querySelector('.defcon-title').textContent = 'DEFCON 5';
      defconStatus.textContent = 'NORMAL';
    }

    // Filter counts
    const countAll = this.threats.length;
    const countBlocked = this.threats.filter(t => t.status === 'BLOCKED').length;
    const countBreached = this.threats.filter(t => t.status === 'BREACHED').length;
    const countMonitored = this.threats.filter(t => t.status === 'MONITORED').length;

    document.getElementById('filter-count-all').textContent = countAll;
    document.getElementById('filter-count-blocked').textContent = countBlocked;
    document.getElementById('filter-count-breached').textContent = countBreached;
    document.getElementById('filter-count-monitored').textContent = countMonitored;
  }

  updateSystemTelemetry() {
    const sys = this.system || {};
    if (sys.publicIp) document.getElementById('nav-server-ip').textContent = sys.publicIp;
    if (sys.hostname) document.getElementById('nav-hostname').textContent = sys.hostname;

    if (sys.loadAvg) {
      const load = sys.loadAvg[0];
      document.getElementById('val-cpu-load').textContent = load;
      const cpuPercent = Math.min(100, Math.round(parseFloat(load) * 50));
      document.getElementById('cpu-bar').style.width = `${cpuPercent}%`;
    }

    if (sys.memory) {
      document.getElementById('val-ram-usage').textContent = `${sys.memory.percent}%`;
      document.getElementById('ram-bar').style.width = `${sys.memory.percent}%`;
    }

    if (sys.uptime) {
      document.getElementById('val-uptime').textContent = sys.uptime;
    }
  }

  renderThreatTable(highlightFirst = false) {
    const tbody = document.getElementById('threat-table-body');
    if (!tbody) return;

    const searchTerm = (document.getElementById('threat-search-input')?.value || '').toLowerCase();

    let list = this.threats;
    if (this.activeFilter !== 'ALL') {
      list = list.filter(t => t.status === this.activeFilter);
    }
    if (searchTerm) {
      list = list.filter(t => 
        (t.source_ip || '').toLowerCase().includes(searchTerm) ||
        (t.attack_type || '').toLowerCase().includes(searchTerm) ||
        (t.payload || '').toLowerCase().includes(searchTerm) ||
        (t.rule_name || '').toLowerCase().includes(searchTerm)
      );
    }

    if (list.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="7" style="text-align:center; padding: 40px; color: #64748b;">
            Tidak ada catatan serangan sesuai filter yang dipilih.
          </td>
        </tr>
      `;
      return;
    }

    tbody.innerHTML = list.map((item, idx) => {
      const isBreach = item.status === 'BREACHED';
      const statusClass = isBreach ? 'badge-breached' : (item.status === 'BLOCKED' ? 'badge-blocked' : 'badge-monitored');
      const statusText = isBreach ? '🚨 BREACHED' : (item.status === 'BLOCKED' ? '🛡️ BLOCKED' : '⚠️ MONITORED');

      const vectorClass = this.getVectorClass(item.attack_type);
      const timeStr = this.formatTime(item.timestamp);
      const isNew = highlightFirst && idx === 0 ? 'row-new' : '';

      return `
        <tr class="${isNew} ${isBreach ? 'row-breach' : ''}">
          <td class="time-cell">${timeStr}</td>
          <td>
            <div class="ip-cell">${item.source_ip}</div>
            <div class="ip-geo">${item.country || 'Unknown'} ${item.city && item.city !== 'Unknown' ? '(' + item.city + ')' : ''}</div>
          </td>
          <td>
            <span class="status-badge ${statusClass}">${statusText}</span>
          </td>
          <td>
            <span class="vector-tag ${vectorClass}">${item.attack_type}</span>
          </td>
          <td class="font-mono">${item.target_port || 80}</td>
          <td>
            <span class="payload-snippet" title="${this.escapeHtml(item.payload || '')}">${this.escapeHtml(item.payload || '-')}</span>
          </td>
          <td>
            <div style="display:flex; gap:6px;">
              <button class="cyber-btn cyber-btn-outline cyber-btn-sm" onclick="app.viewThreatDetail(${item.id})">🔍 Detail</button>
              <button class="cyber-btn cyber-btn-danger cyber-btn-sm" onclick="app.quickBan('${item.source_ip}', '${item.attack_type}')">🚫 Ban</button>
            </div>
          </td>
        </tr>
      `;
    }).join('');
  }

  renderBlockedTable(data) {
    const tbody = document.getElementById('blocked-table-body');
    if (!tbody) return;

    if (!data || data.length === 0) {
      tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; padding: 30px; color:#64748b;">Belum ada IP yang diblokir oleh firewall.</td></tr>`;
      return;
    }

    tbody.innerHTML = data.map(item => {
      const isExpired = item.expires_at && new Date(item.expires_at) < new Date();
      const expiresStr = item.expires_at ? new Date(item.expires_at).toLocaleString('id-ID') : 'Permanen';
      const bannedStr = new Date(item.banned_at).toLocaleString('id-ID');

      return `
        <tr>
          <td class="ip-cell" style="color:var(--cyber-cyan);">${item.ip}</td>
          <td>${item.country || 'Unknown'}</td>
          <td>${item.reason || 'Automated Threat'}</td>
          <td class="font-mono" style="font-weight:bold; color:${item.threat_score >= 80 ? 'var(--cyber-red)' : 'var(--cyber-amber)'};">${item.threat_score}</td>
          <td class="time-cell">${bannedStr}</td>
          <td class="time-cell">${expiresStr}</td>
          <td><span class="vector-tag">${item.manual ? 'MANUAL' : 'AUTO-DEFENSE'}</span></td>
          <td style="text-align:center;">
            <button class="cyber-btn cyber-btn-outline cyber-btn-sm" onclick="app.unblockIP('${item.ip}')">Buka Blokir</button>
          </td>
        </tr>
      `;
    }).join('');
  }

  renderWhitelistTable(data) {
    const tbody = document.getElementById('whitelist-table-body');
    if (!tbody) return;

    if (!data || data.length === 0) {
      tbody.innerHTML = `<tr><td colspan="4" style="text-align:center; padding: 20px; color:#64748b;">Belum ada IP di whitelist.</td></tr>`;
      return;
    }

    tbody.innerHTML = data.map(item => `
      <tr>
        <td class="ip-cell" style="color:var(--cyber-green);">${item.ip}</td>
        <td>${item.note || 'Manual'}</td>
        <td class="time-cell">${new Date(item.created_at).toLocaleString('id-ID')}</td>
        <td style="text-align:center;">
          <button class="cyber-btn cyber-btn-outline cyber-btn-sm" onclick="app.removeWhitelist('${item.ip}')">Hapus</button>
        </td>
      </tr>
    `).join('');
  }

  renderAlertLogs(data) {
    const list = document.getElementById('alert-logs-list');
    if (!list) return;

    if (!data || data.length === 0) {
      list.innerHTML = `<div class="empty-state-mini">Belum ada riwayat email alert yang dikirim.</div>`;
      return;
    }

    list.innerHTML = data.map(item => `
      <div class="alert-log-item">
        <div class="alert-log-header">
          <span style="color:${item.status === 'SENT' ? 'var(--cyber-green)' : 'var(--cyber-red)'}; font-weight:bold;">
            ● ${item.status} &rarr; ${item.recipient}
          </span>
          <span class="time-cell">${new Date(item.timestamp).toLocaleTimeString('id-ID')} WIB</span>
        </div>
        <div class="alert-log-subject">${item.subject}</div>
        ${item.error_message ? `<div class="alert-log-meta" style="color:var(--cyber-red);">Error: ${item.error_message}</div>` : ''}
      </div>
    `).join('');
  }

  // --- ACTIONS ---
  async quickBan(ip, reason) {
    if (confirm(`Blokir IP ${ip} ke firewall iptables?`)) {
      try {
        const res = await fetch(this.getApiUrl('/api/blocked'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ip, reason: `Quick Ban: ${reason}`, duration_hours: 24, threat_score: 100 })
        });
        const json = await res.json();
        if (json.success) {
          this.showToast(`IP ${ip} berhasil diblokir!`);
          this.loadBlockedIPs();
          this.loadStats();
        } else {
          alert(json.reason || json.error);
        }
      } catch (e) {
        alert(e.message);
      }
    }
  }

  async unblockIP(ip) {
    if (confirm(`Buka blokir IP ${ip}?`)) {
      try {
        const res = await fetch(this.getApiUrl(`/api/blocked/${encodeURIComponent(ip)}`), {
          method: 'DELETE',
          headers: { 'Content-Type': 'application/json' }
        });
        const json = await res.json();
        this.showToast(`IP ${ip} telah di-unblock dari firewall.`);
        this.loadBlockedIPs();
        this.loadStats();
      } catch (e) {
        alert(e.message);
      }
    }
  }

  async removeWhitelist(ip) {
    if (confirm(`Hapus ${ip} dari whitelist?`)) {
      try {
        await fetch(this.getApiUrl(`/api/whitelist/${encodeURIComponent(ip)}`), {
          method: 'DELETE',
          headers: { 'Content-Type': 'application/json' }
        });
        this.showToast(`IP ${ip} dihapus dari whitelist.`);
        this.loadWhitelist();
      } catch (e) {
        alert(e.message);
      }
    }
  }

  viewThreatDetail(id) {
    const item = this.threats.find(t => t.id === id);
    if (!item) return;

    const modal = document.getElementById('modal-threat-detail');
    const body = document.getElementById('threat-detail-body');
    if (!modal || !body) return;

    const isBreach = item.status === 'BREACHED';

    body.innerHTML = `
      <table class="cyber-table">
        <tr>
          <td style="width:30%; color:#94a3b8; font-weight:bold;">ID Insiden</td>
          <td class="font-mono">#${item.id}</td>
        </tr>
        <tr>
          <td style="color:#94a3b8; font-weight:bold;">Waktu Kejadian</td>
          <td class="font-mono">${new Date(item.timestamp).toLocaleString('id-ID')} WIB</td>
        </tr>
        <tr>
          <td style="color:#94a3b8; font-weight:bold;">IP Penyerang</td>
          <td class="font-mono" style="color:#f43f5e; font-weight:bold;">${item.source_ip} (${item.country || 'Unknown'}, ${item.city || '-'})</td>
        </tr>
        <tr>
          <td style="color:#94a3b8; font-weight:bold;">Status Pertahanan</td>
          <td>
            <span class="status-badge ${isBreach ? 'badge-breached' : 'badge-blocked'}">
              ${isBreach ? '🚨 SERANGAN BERHASIL MASUK / BREACH' : '🛡️ SERANGAN BERHASIL DIBLOKIR SISTEM'}
            </span>
          </td>
        </tr>
        <tr>
          <td style="color:#94a3b8; font-weight:bold;">Vektor &amp; Port</td>
          <td>${item.attack_type} (Port ${item.target_port || 80} / ${item.service || 'HTTP'})</td>
        </tr>
        <tr>
          <td style="color:#94a3b8; font-weight:bold;">Rule Terpicu</td>
          <td>${item.rule_name || '-'}</td>
        </tr>
        <tr>
          <td style="color:#94a3b8; font-weight:bold;">Tindakan Sistem</td>
          <td>${item.action_taken || 'Logged'}</td>
        </tr>
      </table>
      <div style="margin-top: 14px;">
        <label style="font-size:12px; font-weight:bold; color:#94a3b8; display:block; margin-bottom:6px;">Cuplikan Log / Raw Payload:</label>
        <div style="background:#060913; border:1px solid #1e293b; border-radius:6px; padding:12px; font-family:'JetBrains Mono',monospace; font-size:12px; color:#38bdf8; word-break:break-all; max-height:180px; overflow-y:auto;">
          ${this.escapeHtml(item.payload || '')}
        </div>
      </div>
    `;

    modal.classList.add('open');
  }

  // --- CHARTS INITIALIZATION ---
  initCharts() {
    if (typeof Chart === 'undefined') return;

    // 1. Timeline Area Chart
    const ctxTimeline = document.getElementById('chart-attack-timeline')?.getContext('2d');
    if (ctxTimeline && !this.timelineChart) {
      this.timelineChart = new Chart(ctxTimeline, {
        type: 'line',
        data: {
          labels: ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'],
          datasets: [
            {
              label: 'Serangan Diblokir (Mitigated)',
              data: [0, 0, 0, 0, 0, 0],
              borderColor: '#00f0ff',
              backgroundColor: 'rgba(0, 240, 255, 0.1)',
              fill: true,
              tension: 0.4,
              borderWidth: 2
            },
            {
              label: 'Insiden Kritis / Breach',
              data: [0, 0, 0, 0, 0, 0],
              borderColor: '#ff0055',
              backgroundColor: 'rgba(255, 0, 85, 0.15)',
              fill: true,
              tension: 0.4,
              borderWidth: 2
            }
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { labels: { color: '#94a3b8', font: { family: 'Outfit' } } }
          },
          scales: {
            x: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#64748b' } },
            y: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#64748b' } }
          }
        }
      });
    }

    // 2. Vectors Doughnut Chart
    const ctxVectors = document.getElementById('chart-attack-vectors')?.getContext('2d');
    if (ctxVectors && !this.vectorsChart) {
      this.vectorsChart = new Chart(ctxVectors, {
        type: 'doughnut',
        data: {
          labels: ['SSH Brute Force', 'SQL Injection', 'Path Traversal', 'XSS', 'Scanners'],
          datasets: [{
            data: [1, 1, 1, 1, 1],
            backgroundColor: ['#f59e0b', '#ec4899', '#ef4444', '#8b5cf6', '#06b6d4'],
            borderColor: '#0d1527',
            borderWidth: 2
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { position: 'right', labels: { color: '#94a3b8', font: { family: 'Outfit', size: 11 } } }
          }
        }
      });
    }

    this.updateCharts();
  }

  updateCharts() {
    const s = this.stats || {};

    // Update timeline
    if (this.timelineChart && s.hourlyVolume && s.hourlyVolume.length > 0) {
      const labels = s.hourlyVolume.map(h => h.hour);
      const totalCounts = s.hourlyVolume.map(h => h.count);
      const breachCounts = s.hourlyVolume.map(h => h.breaches || 0);

      this.timelineChart.data.labels = labels;
      this.timelineChart.data.datasets[0].data = totalCounts;
      this.timelineChart.data.datasets[1].data = breachCounts;
      this.timelineChart.update('none');
    }

    // Update vectors
    if (this.vectorsChart && s.vectorStats && s.vectorStats.length > 0) {
      const labels = s.vectorStats.map(v => v.attack_type);
      const counts = s.vectorStats.map(v => v.count);

      this.vectorsChart.data.labels = labels;
      this.vectorsChart.data.datasets[0].data = counts;
      this.vectorsChart.update('none');
    }

    // Top attackers list
    const topListEl = document.getElementById('top-attackers-list');
    if (topListEl && s.topIPs) {
      topListEl.innerHTML = s.topIPs.map(item => `
        <div class="top-item">
          <div class="top-ip-info">
            <span>🌐</span>
            <span>${item.source_ip}</span>
            <span style="color:#64748b; font-size:11px;">(${item.country || 'Unknown'})</span>
          </div>
          <div class="top-count">${item.attack_count} attacks</div>
        </div>
      `).join('');
    }
  }

  // --- HELPERS ---
  showToast(message, type = 'default') {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `cyber-toast ${type === 'danger' ? 'toast-danger' : ''}`;
    toast.innerHTML = `<span>${type === 'danger' ? '🚨' : '🛡️'}</span> <span>${message}</span>`;

    container.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(100%)';
      setTimeout(() => toast.remove(), 300);
    }, 4000);
  }

  getVectorClass(type) {
    if (!type) return '';
    const t = type.toUpperCase();
    if (t.includes('SSH')) return 'ssh';
    if (t.includes('SQL')) return 'sqli';
    if (t.includes('XSS')) return 'xss';
    if (t.includes('TRAVERSAL') || t.includes('LFI')) return 'traversal';
    if (t.includes('SCANNER')) return 'scanner';
    return '';
  }

  formatTime(isoStr) {
    if (!isoStr) return '--:--:--';
    try {
      const d = new Date(isoStr);
      return d.toLocaleTimeString('id-ID');
    } catch (e) {
      return isoStr;
    }
  }

  escapeHtml(str) {
    return (str || '').toString()
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }
}

// Global instance
let app;
document.addEventListener('DOMContentLoaded', () => {
  app = new DashSecApp();
});
