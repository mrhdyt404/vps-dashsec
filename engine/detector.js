const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const https = require('node:https');
const db = require('./database');
const firewall = require('./firewall');
const notifier = require('./notifier');
const config = require('../config.json');

class ThreatDetector {
  constructor() {
    this.wsBroadcast = null; // callback injected by server.js
    this.geoCache = new Map();
    this.sshFailTracker = new Map(); // ip -> { count, lastSeen, user }
    this.webReqTracker = new Map(); // ip -> { timestamps: [] }
    this.logOffsets = new Map(); // filepath -> byte offset

    // Pre-cache known local IPs
    this.geoCache.set('127.0.0.1', { country: 'Localhost', city: 'Internal', country_code: 'LO' });
    this.geoCache.set('103.179.56.154', { country: 'Indonesia', city: 'Jakarta', country_code: 'ID' });
    this.geoCache.set('180.248.111.231', { country: 'Indonesia', city: 'Bandung', country_code: 'ID' });
  }

  setBroadcaster(fn) {
    this.wsBroadcast = fn;
  }

  broadcast(event, data) {
    if (typeof this.wsBroadcast === 'function') {
      try {
        this.wsBroadcast({ event, data });
      } catch (e) {
        console.error('[Detector] Broadcast error:', e.message);
      }
    }
  }

  async resolveGeoIP(ip) {
    if (!ip || ip === '127.0.0.1' || ip === '::1' || ip.startsWith('10.') || ip.startsWith('192.168.')) {
      return { country: 'Local/Private', city: 'Private Network', country_code: 'LO' };
    }
    if (this.geoCache.has(ip)) {
      return this.geoCache.get(ip);
    }

    return new Promise((resolve) => {
      const req = http.get(`http://ip-api.com/json/${ip}?fields=status,country,countryCode,city,org`, { timeout: 2000 }, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          try {
            const parsed = JSON.parse(data);
            if (parsed.status === 'success') {
              const geo = {
                country: parsed.country || 'Unknown',
                city: parsed.city || 'Unknown',
                country_code: parsed.countryCode || 'UN',
                org: parsed.org || ''
              };
              this.geoCache.set(ip, geo);
              return resolve(geo);
            }
          } catch (e) {}
          const fallback = { country: 'Unknown', city: 'Unknown', country_code: 'UN' };
          this.geoCache.set(ip, fallback);
          resolve(fallback);
        });
      });

      req.on('error', () => {
        const fallback = { country: 'Unknown', city: 'Unknown', country_code: 'UN' };
        this.geoCache.set(ip, fallback);
        resolve(fallback);
      });
      req.on('timeout', () => {
        req.destroy();
        const fallback = { country: 'Unknown', city: 'Unknown', country_code: 'UN' };
        this.geoCache.set(ip, fallback);
        resolve(fallback);
      });
    });
  }

  // --- Threat Handling & Dispatch ---
  async handleThreatEvent({
    ip,
    attack_type,
    target_port = 80,
    service = 'HTTP',
    payload = '',
    severity = 'HIGH',
    status = 'BLOCKED', // 'BLOCKED' or 'BREACHED' or 'MONITORED'
    rule_name = 'Threat Rule',
    action_taken = 'Logged',
    isHydrating = false
  }) {
    if (!ip) return;

    const geo = await this.resolveGeoIP(ip);
    const isWhitelisted = firewall.isWhitelisted(ip);

    if (isWhitelisted && status !== 'BREACHED') {
      return; // Ignore whitelisted IPs for non-breach attacks
    }

    // Auto-block logic
    let blockedResult = null;
    if (status === 'BLOCKED' || severity === 'CRITICAL' || severity === 'HIGH') {
      if (!isWhitelisted) {
        blockedResult = firewall.blockIP({
          ip,
          reason: `${attack_type}: ${rule_name}`,
          threat_score: severity === 'CRITICAL' ? 100 : (severity === 'HIGH' ? 80 : 50),
          duration_hours: config.detection.auto_ban_duration_hours || 24,
          country: geo.country,
          country_code: geo.country_code
        });
        action_taken = blockedResult.success ? 'Auto-Blocked via iptables (DROP)' : 'Monitoring (Whitelisted/Active)';
      }
    }

    // Record in SQLite DB
    const threatId = db.addThreatLog({
      ip,
      country: geo.country,
      city: geo.city,
      country_code: geo.country_code,
      attack_type,
      target_port,
      service,
      payload,
      severity,
      status,
      rule_name,
      action_taken
    });

    const threatData = {
      id: threatId,
      timestamp: new Date().toISOString(),
      source_ip: ip,
      country: geo.country,
      city: geo.city,
      country_code: geo.country_code,
      attack_type,
      target_port,
      service,
      payload,
      severity,
      status,
      rule_name,
      action_taken
    };

    // Broadcast live to WebSocket clients
    this.broadcast('THREAT_DETECTED', threatData);
    if (blockedResult && blockedResult.success) {
      this.broadcast('IP_BLOCKED', { ip, country: geo.country, reason: `${attack_type}: ${rule_name}` });
    }

    // Send SMTP email alert if breached or critical (only for live events, not historical hydration)
    if (!isHydrating && (status === 'BREACHED' || (status === 'BLOCKED' && config.smtp.notify_on_block))) {
      notifier.sendAttackAlert({
        threatId,
        ip,
        country: geo.country,
        attackType: attack_type,
        targetPort: target_port,
        service,
        payload,
        severity,
        status,
        ruleName: rule_name,
        actionTaken: action_taken
      }).catch(err => console.error('[Detector] Alert send error:', err.message));
    }
  }

  // --- SSH Log Analysis ---
  processAuthLine(line, isHydrating = false) {
    if (!line || !line.trim()) return;

    // 1. SSH Failed password
    // e.g.: Failed password for invalid user admin from 198.51.100.2 port 49152 ssh2
    // e.g.: Failed password for root from 198.51.100.2 port 49152 ssh2
    let match = line.match(/sshd.*: Failed password for (invalid user )?(\S+) from (\S+) port (\d+)/i);
    if (match) {
      const user = match[2];
      const ip = match[3];
      const port = parseInt(match[4], 10) || 22;

      this.trackSshFailure(ip, user, port, line, 'SSH Failed Password Brute Force', isHydrating);
      return;
    }

    // 2. SSH Invalid user
    match = line.match(/sshd.*: Invalid user (\S+) from (\S+) port (\d+)/i);
    if (match) {
      const user = match[1];
      const ip = match[2];
      const port = parseInt(match[3], 10) || 22;

      this.trackSshFailure(ip, user, port, line, 'SSH Invalid Username Probe', isHydrating);
      return;
    }

    // 3. Preauth connection closed flood
    match = line.match(/sshd.*: Connection closed by (?:invalid user \S+ )?(\d+\.\d+\.\d+\.\d+) port (\d+) \[preauth\]/i);
    if (match) {
      const ip = match[1];
      const port = parseInt(match[2], 10) || 22;
      this.trackSshPreauth(ip, port, line, isHydrating);
      return;
    }

    // 4. SSH Accepted login (Detect possible unauthorized intrusion / breach)
    match = line.match(/sshd.*: Accepted (password|publickey) for (\S+) from (\S+) port (\d+)/i);
    if (match) {
      const authMethod = match[1];
      const user = match[2];
      const ip = match[3];
      const port = parseInt(match[4], 10) || 22;

      const isWhitelisted = firewall.isWhitelisted(ip);
      if (!isWhitelisted) {
        // High severity / Breach alert: Login from untrusted public IP!
        this.handleThreatEvent({
          ip,
          attack_type: 'UNAUTHORIZED_SSH_LOGIN',
          target_port: port,
          service: 'SSH',
          payload: `Successful ${authMethod} login for user '${user}' from UNTRUSTED IP ${ip} (${line})`,
          severity: 'CRITICAL',
          status: 'BREACHED',
          rule_name: 'Untrusted IP SSH Login Detection',
          action_taken: 'BREACH ALERT DISPATCHED TO SMTP & MONITORED',
          isHydrating
        });
      }
      return;
    }
  }

  trackSshFailure(ip, user, port, rawLine, reason, isHydrating = false) {
    const maxAttempts = config.detection.ssh_max_attempts || 3;
    const windowMs = (config.detection.ssh_time_window_sec || 300) * 1000;
    const now = Date.now();

    const tracker = this.sshFailTracker.get(ip) || { count: 0, firstSeen: now, lastSeen: now, users: new Set() };
    if (now - tracker.firstSeen > windowMs) {
      tracker.count = 0;
      tracker.firstSeen = now;
      tracker.users.clear();
    }

    tracker.count++;
    tracker.lastSeen = now;
    tracker.users.add(user);
    this.sshFailTracker.set(ip, tracker);

    const isExceeded = tracker.count >= maxAttempts;

    this.handleThreatEvent({
      ip,
      attack_type: 'SSH_BRUTE_FORCE',
      target_port: port,
      service: 'SSH',
      payload: `User target: '${user}' (Attempts: ${tracker.count}/${maxAttempts}) | Log: ${rawLine}`,
      severity: isExceeded ? 'HIGH' : 'MEDIUM',
      status: isExceeded ? 'BLOCKED' : 'MONITORED',
      rule_name: reason,
      action_taken: isExceeded ? 'Auto-Blocked via iptables' : `Attempt ${tracker.count} of ${maxAttempts}`,
      isHydrating
    });
  }

  trackSshPreauth(ip, port, rawLine, isHydrating = false) {
    const tracker = this.sshFailTracker.get(ip) || { count: 0, firstSeen: Date.now(), lastSeen: Date.now(), users: new Set() };
    tracker.count++;
    tracker.lastSeen = Date.now();
    this.sshFailTracker.set(ip, tracker);

    if (tracker.count >= 5) {
      this.handleThreatEvent({
        ip,
        attack_type: 'SSH_CONNECTION_FLOOD',
        target_port: port,
        service: 'SSH',
        payload: `Rapid preauth connection drop attempts (${tracker.count}) | ${rawLine}`,
        severity: 'HIGH',
        status: 'BLOCKED',
        rule_name: 'SSH Preauth Flood Rule',
        action_taken: 'Auto-Blocked via iptables',
        isHydrating
      });
    }
  }

  // --- Web Access Log Analysis (WAF) ---
  processWebLine(line, serviceName = 'Apache', isHydrating = false) {
    if (!line || !line.trim()) return;

    // Standard Combined / VHost format parser:
    // ::1 - - [18/Aug/2026:13:31:14 +0700] "OPTIONS * HTTP/1.0" 200 126 "-" "Mozilla/..."
    // 139.135.59.230 - - [18/Aug/2026:13:50:13 +0700] "GET /test HTTP/1.0" 400 523 "-" "-"
    const match = line.match(/^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([^"]*)"\s+(\d{3})\s+(\S+)\s+"([^"]*)"\s+"([^"]*)"/);
    if (!match) {
      // Check for raw exploit lines
      const simpleMatch = line.match(/^(\S+)\s+.*?"([^"]*)"\s+(\d{3})/);
      if (simpleMatch) {
        this.analyzeWebRequest(simpleMatch[1], simpleMatch[2], parseInt(simpleMatch[3], 10), '', line, serviceName, isHydrating);
      }
      return;
    }

    const ip = match[1];
    const rawReq = match[3];
    const statusCode = parseInt(match[4], 10) || 200;
    const userAgent = match[7] || '';

    this.analyzeWebRequest(ip, rawReq, statusCode, userAgent, line, serviceName, isHydrating);
  }

  analyzeWebRequest(ip, requestLine, statusCode, userAgent, rawLine, serviceName, isHydrating = false) {
    if (!ip || ip === '::1' || ip === '127.0.0.1' && requestLine.includes('OPTIONS *')) {
      return; // Ignore internal apache dummy connections
    }

    const decodedReq = decodeURIComponentSafe(requestLine);
    const fullInspectString = `${decodedReq} ${userAgent}`;

    let attackType = null;
    let ruleName = null;
    let severity = 'HIGH';
    let isBreach = false;

    // 1. SQL Injection Detection
    if (/(union(\s+all)?\s+select|select.+from|benchmark\s*\(|sleep\s*\(\d+\)|waitfor\s+delay|information_schema|load_file\s*\(|into\s+outfile|or\s+['"]?1['"]?\s*=\s*['"]?1|'\s*or\s*'|--|\/\*.*\*\/|;\s*drop\s+table)/i.test(fullInspectString)) {
      attackType = 'SQL_INJECTION';
      ruleName = 'WAF Rule: SQL Injection Signature Match';
      severity = 'HIGH';
      if (statusCode === 200) {
        isBreach = true;
      }
    }
    // 2. Cross-Site Scripting (XSS)
    else if (/(<script|javascript:|onerror\s*=|onload\s*=|alert\s*\(|document\.cookie|eval\s*\(|<svg.+onload|<iframe|fromCharCode)/i.test(fullInspectString)) {
      attackType = 'XSS_ATTACK';
      ruleName = 'WAF Rule: Cross-Site Scripting Payload Match';
      severity = 'HIGH';
      if (statusCode === 200) {
        isBreach = true;
      }
    }
    // 3. Path Traversal / LFI / RFI
    else if (/(\.\.\/|\.\.\\|\%2e\%2e\%2f|\%2e\%2e\/|\/etc\/passwd|\/etc\/shadow|win\.ini|boot\.ini|php:\/\/filter|data:\/\/|expect:\/\/)/i.test(fullInspectString)) {
      attackType = 'PATH_TRAVERSAL';
      ruleName = 'WAF Rule: Directory Traversal / LFI Attempt';
      severity = 'HIGH';
      if (statusCode === 200) {
        isBreach = true; // Critical: File content accessed!
      }
    }
    // 4. Vulnerability Scanners / Bad Bots
    else if (/(sqlmap|nikto|masscan|zgrab|nuclei|gobuster|dirsearch|wpscan|nmap|acunetix|nessus|openvas|censys)/i.test(userAgent) ||
             /(sqlmap|nikto|nuclei)/i.test(decodedReq)) {
      attackType = 'VULN_SCANNER';
      ruleName = `Security Scanner Detected (${userAgent.substring(0, 30)})`;
      severity = 'MEDIUM';
    }
    // 5. Sensitive File Probing / Webshells / Malware Droppers
    else if (/(\/\.git|\/\.env|\/wp-config\.php|\/eval-stdin\.php|\bphpmyadmin\b|\/cgi-bin|\/setup\.cgi|\b(cmd|shell|wso|c99|r57|b374k|alfa)\.php|Mozi\.m|wget%20http)/i.test(fullInspectString)) {
      attackType = 'SENSITIVE_PROBE';
      ruleName = 'WAF Rule: Sensitive Asset / Malware Dropper Probe';
      severity = 'HIGH';
      if (statusCode === 200 && (decodedReq.includes('.env') || decodedReq.includes('.git') || decodedReq.includes('wp-config'))) {
        isBreach = true; // Critical: Sensitive credentials leaked!
      }
    }
    // 6. DoS Rate Limiting
    else {
      const now = Date.now();
      const tracker = this.webReqTracker.get(ip) || { timestamps: [] };
      tracker.timestamps = tracker.timestamps.filter(t => now - t < 10000); // 10s window
      tracker.timestamps.push(now);
      this.webReqTracker.set(ip, tracker);

      const threshold = config.detection.web_dos_threshold || 60;
      if (tracker.timestamps.length > threshold) {
        attackType = 'DOS_BURST';
        ruleName = `Rate Limit Exceeded (${tracker.timestamps.length} req / 10s)`;
        severity = 'HIGH';
      }
    }

    if (attackType) {
      const status = isBreach ? 'BREACHED' : (statusCode >= 400 || statusCode === 301 ? 'BLOCKED' : 'BLOCKED');
      this.handleThreatEvent({
        ip,
        attack_type: attackType,
        target_port: 80,
        service: 'HTTP-WAF',
        payload: `Request: "${requestLine}" | Status: ${statusCode} | UA: ${userAgent.substring(0, 80)}`,
        severity: isBreach ? 'CRITICAL' : severity,
        status,
        rule_name: ruleName,
        action_taken: isBreach ? '🚨 BREACH ALERT DISPATCHED TO SMTP' : 'Auto-Blocked & Defended',
        isHydrating
      });
    }
  }

  // --- Realtime Log File Monitoring ---
  startTailing() {
    console.log('[Detector] Starting live log listeners...');

    // 1. Auth Log
    const authLog = config.logs?.auth_log || '/var/log/auth.log';
    if (fs.existsSync(authLog)) {
      this.watchFileTail(authLog, (line) => this.processAuthLine(line));
      this.hydrateInitialHistory(authLog, (line) => this.processAuthLine(line));
    }

    // 2. Discover all Apache Access Logs in /var/log/apache2/
    const apacheDir = '/var/log/apache2';
    const logFilesToWatch = new Set();

    if (fs.existsSync(apacheDir)) {
      try {
        const files = fs.readdirSync(apacheDir);
        for (const file of files) {
          if (file.endsWith('_access.log') || file === 'access.log' || file === 'other_vhosts_access.log') {
            logFilesToWatch.add(path.join(apacheDir, file));
          }
        }
      } catch (e) {
        console.error('[Detector] Error reading /var/log/apache2 directory:', e.message);
      }
    }

    // Also include any custom configured paths
    const customLogs = config.logs?.apache_access_logs || [];
    for (const logPath of customLogs) {
      if (fs.existsSync(logPath)) {
        logFilesToWatch.add(logPath);
      }
    }

    console.log(`[Detector] Discovered ${logFilesToWatch.size} Apache access log files to monitor.`);
    for (const logPath of logFilesToWatch) {
      this.watchFileTail(logPath, (line) => this.processWebLine(line, path.basename(logPath)));
      this.hydrateInitialHistory(logPath, (line) => this.processWebLine(line, path.basename(logPath)));
    }
  }

  hydrateInitialHistory(filePath, lineHandler) {
    if (!fs.existsSync(filePath)) return;
    try {
      const content = fs.readFileSync(filePath, 'utf8');
      const lines = content.split('\n');
      const recent = lines.slice(-40);
      for (const line of recent) {
        if (line.trim()) {
          lineHandler(line);
        }
      }
      this.logOffsets.set(filePath, fs.statSync(filePath).size);
    } catch (e) {
      console.error(`[Detector] Initial read error on ${filePath}:`, e.message);
    }
  }

  watchFileTail(filePath, lineHandler) {
    if (!fs.existsSync(filePath)) {
      console.warn(`[Detector] Log file not found: ${filePath}`);
      return;
    }

    let currentSize = 0;
    try {
      currentSize = fs.statSync(filePath).size;
      this.logOffsets.set(filePath, currentSize);
    } catch (e) {}

    fs.watchFile(filePath, { interval: 800 }, (curr, prev) => {
      if (curr.size > prev.size) {
        const bytesToRead = curr.size - prev.size;
        const buffer = Buffer.alloc(bytesToRead);
        let fd = null;
        try {
          fd = fs.openSync(filePath, 'r');
          fs.readSync(fd, buffer, 0, bytesToRead, prev.size);
          fs.closeSync(fd);

          const newContent = buffer.toString('utf8');
          const lines = newContent.split('\n');
          for (const line of lines) {
            if (line.trim()) {
              lineHandler(line);
            }
          }
        } catch (err) {
          if (fd) try { fs.closeSync(fd); } catch (e) {}
          console.error(`[Detector] Error reading tail for ${filePath}:`, err.message);
        }
      } else if (curr.size < prev.size) {
        // File rotated
        this.logOffsets.set(filePath, curr.size);
      }
    });

    console.log(`[Detector] Watching ${filePath} (Initial size: ${currentSize} bytes)`);
  }
}

function decodeURIComponentSafe(uri) {
  if (!uri) return '';
  try {
    return decodeURIComponent(uri);
  } catch (e) {
    return uri;
  }
}

module.exports = new ThreatDetector();
