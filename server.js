const http = require('node:http');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const { execSync } = require('node:child_process');
const express = require('express');
const { WebSocketServer, WebSocket } = require('ws');

const config = require('./config.json');
const db = require('./engine/database');
const firewall = require('./engine/firewall');
const notifier = require('./engine/notifier');
const detector = require('./engine/detector');

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ noServer: true });

server.on('upgrade', (request, socket, head) => {
  try {
    const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);
    if (url.pathname === '/ws' || url.pathname === '/dashsec/ws' || url.pathname.endsWith('/ws')) {
      wss.handleUpgrade(request, socket, head, (ws) => {
        wss.emit('connection', ws, request);
      });
    } else {
      socket.destroy();
    }
  } catch (err) {
    socket.destroy();
  }
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static frontend
app.use(express.static(path.join(__dirname, 'public')));
app.use('/dashsec', express.static(path.join(__dirname, 'public')));

// Helper to get system statistics
function getSystemStats() {
  const cpus = os.cpus();
  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  const usedMem = totalMem - freeMem;
  const memUsagePercent = Math.round((usedMem / totalMem) * 100);
  const loadAvg = os.loadavg();
  const uptime = os.uptime();

  let diskUsage = { total: 'N/A', free: 'N/A', used: 'N/A', percent: 0 };
  try {
    const dfOut = execSync('df -h / | tail -1', { encoding: 'utf8' }).trim().split(/\s+/);
    if (dfOut.length >= 5) {
      diskUsage = {
        total: dfOut[1],
        used: dfOut[2],
        free: dfOut[3],
        percent: parseInt(dfOut[4].replace('%', ''), 10) || 0
      };
    }
  } catch (e) {}

  return {
    hostname: os.hostname(),
    platform: os.platform(),
    arch: os.arch(),
    uptime: formatUptime(uptime),
    uptimeSeconds: uptime,
    cpuCount: cpus.length,
    cpuModel: cpus[0]?.model || 'Generic CPU',
    loadAvg: [loadAvg[0].toFixed(2), loadAvg[1].toFixed(2), loadAvg[2].toFixed(2)],
    memory: {
      total: formatBytes(totalMem),
      used: formatBytes(usedMem),
      free: formatBytes(freeMem),
      percent: memUsagePercent
    },
    disk: diskUsage,
    publicIp: config.server.public_ip || '103.179.56.154'
  };
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatUptime(sec) {
  const days = Math.floor(sec / 86400);
  const hours = Math.floor((sec % 86400) / 3600);
  const minutes = Math.floor((sec % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h ${minutes}m`;
  return `${hours}h ${minutes}m`;
}

// WebSocket broadcast helper
function broadcastWs(message) {
  const payload = JSON.stringify(message);
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(payload);
    }
  });
}

// Hook detector into websocket broadcast
detector.setBroadcaster(broadcastWs);

wss.on('connection', (ws) => {
  // Send initial welcome and state
  ws.send(JSON.stringify({
    event: 'INIT',
    data: {
      stats: db.getThreatStats(),
      system: getSystemStats(),
      firewall: firewall.getFirewallStatus(),
      recentThreats: db.getRecentThreats(20)
    }
  }));
});

// Periodic heartbeat & system metrics broadcast
setInterval(() => {
  broadcastWs({
    event: 'SYSTEM_TICK',
    data: {
      system: getSystemStats(),
      threatStats: db.getThreatStats()
    }
  });
}, 3000);

// --- REST API ENDPOINTS ---

// 1. Dashboard Comprehensive Stats
app.get('/api/stats', (req, res) => {
  try {
    const stats = db.getThreatStats();
    const system = getSystemStats();
    const fw = firewall.getFirewallStatus();
    res.json({ success: true, stats, system, firewall: fw });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 2. Threat Logs Feed
app.get('/api/threats', (req, res) => {
  try {
    const limit = parseInt(req.query.limit, 10) || 50;
    const status = req.query.status || null;
    const search = req.query.search || null;
    const threats = db.getRecentThreats(limit, status, search);
    res.json({ success: true, count: threats.length, data: threats });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 3. Blocked IPs Management
app.get('/api/blocked', (req, res) => {
  try {
    const blocked = db.getAllBlockedIPs();
    res.json({ success: true, data: blocked });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/blocked', async (req, res) => {
  try {
    const { ip, reason, duration_hours, threat_score } = req.body;
    if (!ip) return res.status(400).json({ success: false, error: 'IP address is required' });

    const geo = await detector.resolveGeoIP(ip);
    const result = firewall.blockIP({
      ip,
      reason: reason || 'Manual Admin Ban',
      threat_score: parseInt(threat_score, 10) || 100,
      duration_hours: parseInt(duration_hours, 10) || 24,
      manual: 1,
      country: geo.country,
      country_code: geo.country_code
    });

    if (!result.success) {
      return res.status(400).json(result);
    }

    broadcastWs({ event: 'IP_BLOCKED', data: { ip, reason, country: geo.country } });
    res.json({ success: true, message: `IP ${ip} successfully blocked!`, data: result });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.delete('/api/blocked/:ip', (req, res) => {
  try {
    const ip = req.params.ip;
    const result = firewall.unblockIP(ip);
    broadcastWs({ event: 'IP_UNBLOCKED', data: { ip } });
    res.json({ success: true, message: `IP ${ip} unblocked successfully!`, data: result });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/firewall/flush', (req, res) => {
  try {
    const result = firewall.flushAll();
    broadcastWs({ event: 'FIREWALL_FLUSHED', data: {} });
    res.json({ success: true, message: 'All bans flushed from firewall', data: result });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 4. Whitelist Management
app.get('/api/whitelist', (req, res) => {
  try {
    const whitelist = db.getWhitelistedIPs();
    res.json({ success: true, data: whitelist });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/whitelist', (req, res) => {
  try {
    const { ip, note } = req.body;
    if (!ip) return res.status(400).json({ success: false, error: 'IP address is required' });

    db.addWhitelistedIP(ip, note || 'Manual Whitelist');
    firewall.syncWhitelist();
    // If IP was banned, unban it
    firewall.unblockIP(ip);

    res.json({ success: true, message: `IP ${ip} whitelisted successfully!` });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.delete('/api/whitelist/:ip', (req, res) => {
  try {
    const ip = req.params.ip;
    db.removeWhitelistedIP(ip);
    firewall.syncWhitelist();
    res.json({ success: true, message: `IP ${ip} removed from whitelist.` });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 5. SMTP Settings & Email Alerts
app.get('/api/smtp', (req, res) => {
  try {
    const smtp = db.getSMTPSettings();
    // Mask password
    const safeSmtp = { ...smtp, auth_pass: smtp.auth_pass ? '********' : '' };
    res.json({ success: true, data: safeSmtp });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/smtp', (req, res) => {
  try {
    const { host, port, secure, auth_user, auth_pass, sender_email, sender_name, recipient_email, notify_on_breach, notify_on_block } = req.body;

    const updateData = {
      host,
      port: parseInt(port, 10) || 587,
      secure: Boolean(secure),
      auth_user,
      sender_email,
      sender_name,
      recipient_email: recipient_email || 'mrhxxx7@gmail.com',
      notify_on_breach: Boolean(notify_on_breach),
      notify_on_block: Boolean(notify_on_block)
    };

    if (auth_pass && auth_pass !== '********') {
      updateData.auth_pass = auth_pass;
    }

    db.updateSMTPSettings(updateData);
    res.json({ success: true, message: 'SMTP settings updated successfully!' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/smtp/test', async (req, res) => {
  try {
    const custom = (req.body && req.body.host) ? req.body : null;
    const result = await notifier.sendTestEmail(custom);
    res.json(result);
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/api/alerts', (req, res) => {
  try {
    const logs = db.getRecentAlertLogs(50);
    res.json({ success: true, data: logs });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 6. Machine Learning & AI Endpoints
const mlEngine = require('./engine/ml_engine');

app.get('/api/ml/stats', (req, res) => {
  try {
    const stats = db.getMLStats();
    res.json({
      success: true,
      stats: {
        ...stats,
        sensitivity: mlEngine.sensitivity,
        threshold: mlEngine.thresholds[mlEngine.sensitivity],
        maliciousVocabCount: mlEngine.maliciousTokens.size,
        benignVocabCount: mlEngine.benignTokens.size
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/api/ml/insights', (req, res) => {
  try {
    const limit = parseInt(req.query.limit, 10) || 50;
    const filterClass = req.query.classification || null;
    const insights = db.getRecentMLInsights(limit, filterClass);
    res.json({ success: true, count: insights.length, data: insights });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/api/ml/reputation', (req, res) => {
  try {
    const reputations = db.getTopAnomalousIPs(20);
    res.json({ success: true, data: reputations });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/ml/sensitivity', (req, res) => {
  try {
    const { level } = req.body;
    const ok = mlEngine.setSensitivity(level);
    if (!ok) return res.status(400).json({ success: false, error: 'Invalid level. Use AGGRESSIVE, BALANCED, or CONSERVATIVE' });
    res.json({ success: true, message: `ML sensitivity updated to ${level}` });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/ml/train', (req, res) => {
  try {
    mlEngine.persistModelState();
    res.json({
      success: true,
      message: 'Machine Learning Model re-trained and optimized successfully!',
      stats: {
        maliciousTokens: mlEngine.maliciousTokens.size,
        benignTokens: mlEngine.benignTokens.size
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 6. Security Attack Simulator (Test Mode)
app.post('/api/simulate', async (req, res) => {
  try {
    const { type, ip = '198.51.100.77', testPayload } = req.body;
    console.log(`[Simulator] Running simulation test for type: ${type} from IP: ${ip}`);

    if (type === 'SSH_BRUTE_FORCE') {
      // Simulate 4 failed SSH attempts
      for (let i = 1; i <= 4; i++) {
        detector.processAuthLine(`2026-08-18T14:40:00+07:00 HNTR sshd[9999]: Failed password for invalid user admin from ${ip} port 52140 ssh2`);
      }
      return res.json({ success: true, message: `Simulated 4 failed SSH attempts from ${ip}. Threat scored & Auto-Blocked!` });
    }

    if (type === 'SQL_INJECTION') {
      detector.processWebLine(`${ip} - - [18/Aug/2026:14:40:00 +0700] "GET /products.php?id=1%20UNION%20SELECT%201,username,password%20FROM%20users-- HTTP/1.1" 403 1250 "-" "Mozilla/5.0"`);
      return res.json({ success: true, message: `Simulated SQL Injection probe from ${ip}. WAF triggered & Auto-Blocked!` });
    }

    if (type === 'PATH_TRAVERSAL') {
      detector.processWebLine(`${ip} - - [18/Aug/2026:14:40:00 +0700] "GET /../../../../etc/passwd HTTP/1.1" 403 890 "-" "sqlmap/1.7"`);
      return res.json({ success: true, message: `Simulated Path Traversal LFI exploit from ${ip}. Auto-Blocked!` });
    }

    if (type === 'VULN_SCANNER') {
      detector.processWebLine(`${ip} - - [18/Aug/2026:14:40:00 +0700] "GET /robots.txt HTTP/1.1" 200 450 "-" "Mozilla/5.0 (compatible; Nikto/2.1.6)"`);
      return res.json({ success: true, message: `Simulated Nikto Scanner detection from ${ip}. Logged and analyzed!` });
    }

    if (type === 'BREACH_ALERT') {
      // Critical Breach Simulation: Triggers immediate SMTP email alert to mrhxxx7@gmail.com
      await detector.handleThreatEvent({
        ip: ip || '203.0.113.88',
        attack_type: 'CRITICAL_BREACH_SIMULATION',
        target_port: 80,
        service: 'HTTP-WebExploit',
        payload: 'SIMULATED EXPLOIT: HTTP 200 OK accessed sensitive database credentials via /.env probe',
        severity: 'CRITICAL',
        status: 'BREACHED',
        rule_name: 'Simulated Breach Alert Trigger',
        action_taken: '🚨 CRITICAL BREACH ALERT DISPATCHED TO mrhxxx7@gmail.com'
      });
      return res.json({ success: true, message: `Simulated Critical Breach Alert dispatched! Email sent to mrhxxx7@gmail.com.` });
    }

    if (type === 'ML_ZERO_DAY') {
      // Obfuscated Zero-Day Exploit with high entropy to test Machine Learning Anomaly Detection
      const obfuscatedPayload = `${ip} - - [18/Aug/2026:15:40:00 +0700] "GET /gateway/api/v1/eval?data=JTI1M2MlNzczJTYzJTY1JTc0JTIwJTJmJTJmJTI1MmYlMjUyZmV0YyUyNTJmcGFzc3dk&sig=0x756e696f6e2073656c656374 HTTP/1.1" 200 4800 "-" "Mozilla/5.0 (CustomZeroDayBot/2.4; EntropyScan)"`;
      detector.processWebLine(obfuscatedPayload, 'Apache-AI-Test');
      return res.json({
        success: true,
        message: `Simulated Zero-Day Obfuscated Payload from ${ip}. Machine Learning Engine triggered autonomous detection!`
      });
    }

    res.status(400).json({ success: false, error: 'Unknown simulation type' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Fallback to SPA index.html
app.use((req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = config.server.port || 8443;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`====================================================`);
  console.log(`🛡️  DASHSEC VPS CYBER DEFENSE & MONITORING SYSTEM`);
  console.log(`====================================================`);
  console.log(`🚀 Dashboard UI: http://localhost:${PORT}/ or http://${config.server.public_ip || '103.179.56.154'}:${PORT}/`);
  console.log(`📡 WebSocket:    ws://localhost:${PORT}/ws`);
  console.log(`📧 Recipient:    ${config.smtp.recipient_email}`);
  console.log(`🛡️  Firewall:     Chain ${firewall.getFirewallStatus().chain} Active`);
  console.log(`====================================================`);

  // Start log tailing
  detector.startTailing();
});
