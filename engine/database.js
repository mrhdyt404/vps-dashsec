const { DatabaseSync } = require('node:sqlite');
const path = require('node:path');
const fs = require('node:fs');

const DB_PATH = path.join(__dirname, '..', 'dashsec.db');

class DashSecDB {
  constructor() {
    this.db = new DatabaseSync(DB_PATH);
    this.initTables();
  }

  initTables() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS threat_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        source_ip TEXT NOT NULL,
        country TEXT DEFAULT 'Unknown',
        city TEXT DEFAULT 'Unknown',
        country_code TEXT DEFAULT 'UN',
        attack_type TEXT NOT NULL,
        target_port INTEGER DEFAULT 80,
        service TEXT DEFAULT 'HTTP',
        payload TEXT,
        severity TEXT DEFAULT 'MEDIUM',
        status TEXT DEFAULT 'BLOCKED', -- BLOCKED, BREACHED, MONITORED
        rule_name TEXT,
        action_taken TEXT
      );

      CREATE TABLE IF NOT EXISTS blocked_ips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT UNIQUE NOT NULL,
        reason TEXT,
        threat_score INTEGER DEFAULT 100,
        banned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        expires_at DATETIME,
        is_active INTEGER DEFAULT 1,
        manual INTEGER DEFAULT 0,
        country TEXT DEFAULT 'Unknown',
        country_code TEXT DEFAULT 'UN'
      );

      CREATE TABLE IF NOT EXISTS whitelisted_ips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT UNIQUE NOT NULL,
        note TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS smtp_config (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        host TEXT DEFAULT 'smtp.gmail.com',
        port INTEGER DEFAULT 587,
        secure INTEGER DEFAULT 0,
        auth_user TEXT DEFAULT '',
        auth_pass TEXT DEFAULT '',
        sender_email TEXT DEFAULT 'dashsec-alert@hntr.local',
        sender_name TEXT DEFAULT 'DashSec VPS Defense',
        recipient_email TEXT DEFAULT 'mrhxxx7@gmail.com',
        notify_on_breach INTEGER DEFAULT 1,
        notify_on_block INTEGER DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS alert_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        recipient TEXT NOT NULL,
        subject TEXT NOT NULL,
        threat_id INTEGER,
        status TEXT DEFAULT 'SENT',
        error_message TEXT,
        details TEXT
      );

      -- Machine Learning & AI Intelligence Tables
      CREATE TABLE IF NOT EXISTS ml_insights (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        ip TEXT NOT NULL,
        attack_probability REAL DEFAULT 0.0,
        anomaly_score REAL DEFAULT 0.0,
        entropy REAL DEFAULT 0.0,
        token_score REAL DEFAULT 0.0,
        velocity_score REAL DEFAULT 0.0,
        classification TEXT DEFAULT 'BENIGN', -- BENIGN, SUSPICIOUS, MALICIOUS, PREEMPTIVE_BLOCK
        model_confidence REAL DEFAULT 0.0,
        payload_snippet TEXT,
        action_taken TEXT DEFAULT 'Analyzed'
      );

      CREATE TABLE IF NOT EXISTS ml_ip_reputation (
        ip TEXT PRIMARY KEY,
        reputation_score REAL DEFAULT 100.0, -- 100 is cleanest, 0 is worst
        total_requests INTEGER DEFAULT 1,
        anomaly_count INTEGER DEFAULT 0,
        last_anomaly REAL DEFAULT 0.0,
        last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS ml_model_state (
        key TEXT PRIMARY KEY,
        value TEXT,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );

      CREATE INDEX IF NOT EXISTS idx_threat_ip ON threat_logs(source_ip);
      CREATE INDEX IF NOT EXISTS idx_threat_time ON threat_logs(timestamp);
      CREATE INDEX IF NOT EXISTS idx_threat_status ON threat_logs(status);
      CREATE INDEX IF NOT EXISTS idx_blocked_ip ON blocked_ips(ip);
      CREATE INDEX IF NOT EXISTS idx_blocked_active ON blocked_ips(is_active);
      CREATE INDEX IF NOT EXISTS idx_ml_ip ON ml_insights(ip);
      CREATE INDEX IF NOT EXISTS idx_ml_time ON ml_insights(timestamp);
      CREATE INDEX IF NOT EXISTS idx_ml_class ON ml_insights(classification);
    `);

    // Ensure default SMTP record exists
    const checkSmtp = this.db.prepare('SELECT id FROM smtp_config WHERE id = 1').get();
    if (!checkSmtp) {
      this.db.prepare(`
        INSERT INTO smtp_config (id, host, port, secure, auth_user, auth_pass, sender_email, sender_name, recipient_email, notify_on_breach, notify_on_block)
        VALUES (1, 'smtp.gmail.com', 587, 0, '', '', 'dashsec-alert@hntr.local', 'DashSec VPS Defense', 'mrhxxx7@gmail.com', 1, 0)
      `).run();
    }
  }

  // --- Threat Logs ---
  addThreatLog({ ip, country, city, country_code, attack_type, target_port, service, payload, severity, status, rule_name, action_taken }) {
    const stmt = this.db.prepare(`
      INSERT INTO threat_logs (source_ip, country, city, country_code, attack_type, target_port, service, payload, severity, status, rule_name, action_taken)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    const result = stmt.run(
      ip,
      country || 'Unknown',
      city || 'Unknown',
      country_code || 'UN',
      attack_type,
      target_port || 80,
      service || 'HTTP',
      payload || '',
      severity || 'MEDIUM',
      status || 'BLOCKED',
      rule_name || 'Generic Threat Rule',
      action_taken || 'Logged'
    );
    return Number(result.lastInsertRowid);
  }

  getRecentThreats(limit = 100, statusFilter = null, search = null) {
    let query = 'SELECT * FROM threat_logs';
    const params = [];
    const conditions = [];

    if (statusFilter && statusFilter !== 'ALL') {
      conditions.push('status = ?');
      params.push(statusFilter);
    }
    if (search) {
      conditions.push('(source_ip LIKE ? OR attack_type LIKE ? OR payload LIKE ? OR rule_name LIKE ?)');
      const s = `%${search}%`;
      params.push(s, s, s, s);
    }

    if (conditions.length > 0) {
      query += ' WHERE ' + conditions.join(' AND ');
    }
    query += ' ORDER BY id DESC LIMIT ?';
    params.push(limit);

    return this.db.prepare(query).all(...params);
  }

  getThreatStats() {
    const totalAttacks = this.db.prepare('SELECT COUNT(*) as count FROM threat_logs').get()?.count || 0;
    const totalBlocked = this.db.prepare("SELECT COUNT(*) as count FROM threat_logs WHERE status = 'BLOCKED'").get()?.count || 0;
    const totalBreached = this.db.prepare("SELECT COUNT(*) as count FROM threat_logs WHERE status = 'BREACHED'").get()?.count || 0;
    const totalMonitored = this.db.prepare("SELECT COUNT(*) as count FROM threat_logs WHERE status = 'MONITORED'").get()?.count || 0;
    const activeBlocks = this.db.prepare('SELECT COUNT(*) as count FROM blocked_ips WHERE is_active = 1').get()?.count || 0;

    const todayAttacks = this.db.prepare("SELECT COUNT(*) as count FROM threat_logs WHERE date(timestamp) = date('now')").get()?.count || 0;
    const todayBreached = this.db.prepare("SELECT COUNT(*) as count FROM threat_logs WHERE date(timestamp) = date('now') AND status = 'BREACHED'").get()?.count || 0;

    // Vectors breakdown
    const vectorStats = this.db.prepare(`
      SELECT attack_type, COUNT(*) as count 
      FROM threat_logs 
      GROUP BY attack_type 
      ORDER BY count DESC 
      LIMIT 10
    `).all();

    // Top Attacker IPs
    const topIPs = this.db.prepare(`
      SELECT source_ip, country, country_code, COUNT(*) as attack_count, MAX(timestamp) as last_seen 
      FROM threat_logs 
      GROUP BY source_ip 
      ORDER BY attack_count DESC 
      LIMIT 10
    `).all();

    // Top Countries
    const topCountries = this.db.prepare(`
      SELECT country, country_code, COUNT(*) as count 
      FROM threat_logs 
      GROUP BY country 
      ORDER BY count DESC 
      LIMIT 10
    `).all();

    // Hourly volume for last 24 hours
    const hourlyVolume = this.db.prepare(`
      SELECT strftime('%H:00', timestamp) as hour, COUNT(*) as count,
             SUM(CASE WHEN status = 'BREACHED' THEN 1 ELSE 0 END) as breaches
      FROM threat_logs 
      WHERE timestamp >= datetime('now', '-24 hours')
      GROUP BY hour 
      ORDER BY timestamp ASC
    `).all();

    return {
      totalAttacks,
      totalBlocked,
      totalBreached,
      totalMonitored,
      activeBlocks,
      todayAttacks,
      todayBreached,
      vectorStats,
      topIPs,
      topCountries,
      hourlyVolume
    };
  }

  // --- Blocked IPs ---
  addBlockedIP({ ip, reason, threat_score = 100, duration_hours = 24, manual = 0, country = 'Unknown', country_code = 'UN' }) {
    const expiresAt = duration_hours === 0 ? null : new Date(Date.now() + duration_hours * 3600 * 1000).toISOString();
    const stmt = this.db.prepare(`
      INSERT INTO blocked_ips (ip, reason, threat_score, expires_at, is_active, manual, country, country_code)
      VALUES (?, ?, ?, ?, 1, ?, ?, ?)
      ON CONFLICT(ip) DO UPDATE SET
        reason = excluded.reason,
        threat_score = excluded.threat_score,
        banned_at = CURRENT_TIMESTAMP,
        expires_at = excluded.expires_at,
        is_active = 1,
        manual = excluded.manual
    `);
    stmt.run(ip, reason, threat_score, expiresAt, manual, country, country_code);
  }

  unblockIP(ip) {
    const stmt = this.db.prepare('UPDATE blocked_ips SET is_active = 0 WHERE ip = ?');
    stmt.run(ip);
  }

  deleteBlockedIP(ip) {
    const stmt = this.db.prepare('DELETE FROM blocked_ips WHERE ip = ?');
    stmt.run(ip);
  }

  getActiveBlockedIPs() {
    return this.db.prepare('SELECT * FROM blocked_ips WHERE is_active = 1 ORDER BY banned_at DESC').all();
  }

  getAllBlockedIPs() {
    return this.db.prepare('SELECT * FROM blocked_ips ORDER BY banned_at DESC LIMIT 200').all();
  }

  isIPBlocked(ip) {
    const row = this.db.prepare('SELECT id FROM blocked_ips WHERE ip = ? AND is_active = 1').get();
    return !!row;
  }

  getExpiredBans() {
    return this.db.prepare(`
      SELECT * FROM blocked_ips 
      WHERE is_active = 1 AND expires_at IS NOT NULL AND expires_at <= CURRENT_TIMESTAMP
    `).all();
  }

  // --- Whitelist ---
  addWhitelistedIP(ip, note = 'Manual Whitelist') {
    const stmt = this.db.prepare(`
      INSERT INTO whitelisted_ips (ip, note) VALUES (?, ?)
      ON CONFLICT(ip) DO UPDATE SET note = excluded.note
    `);
    stmt.run(ip, note);
  }

  removeWhitelistedIP(ip) {
    const stmt = this.db.prepare('DELETE FROM whitelisted_ips WHERE ip = ?');
    stmt.run(ip);
  }

  getWhitelistedIPs() {
    return this.db.prepare('SELECT * FROM whitelisted_ips ORDER BY created_at DESC').all();
  }

  isIPWhitelisted(ip) {
    const row = this.db.prepare('SELECT id FROM whitelisted_ips WHERE ip = ?').get();
    return !!row;
  }

  // --- SMTP Settings ---
  getSMTPSettings() {
    return this.db.prepare('SELECT * FROM smtp_config WHERE id = 1').get();
  }

  updateSMTPSettings({ host, port, secure, auth_user, auth_pass, sender_email, sender_name, recipient_email, notify_on_breach, notify_on_block }) {
    const current = this.getSMTPSettings() || {};
    const stmt = this.db.prepare(`
      UPDATE smtp_config SET
        host = ?,
        port = ?,
        secure = ?,
        auth_user = ?,
        auth_pass = ?,
        sender_email = ?,
        sender_name = ?,
        recipient_email = ?,
        notify_on_breach = ?,
        notify_on_block = ?
      WHERE id = 1
    `);
    stmt.run(
      host ?? current.host,
      port ?? current.port,
      secure !== undefined ? (secure ? 1 : 0) : current.secure,
      auth_user ?? current.auth_user,
      auth_pass !== undefined ? auth_pass : current.auth_pass,
      sender_email ?? current.sender_email,
      sender_name ?? current.sender_name,
      recipient_email ?? current.recipient_email,
      notify_on_breach !== undefined ? (notify_on_breach ? 1 : 0) : current.notify_on_breach,
      notify_on_block !== undefined ? (notify_on_block ? 1 : 0) : current.notify_on_block
    );
  }

  // --- Alert Logs ---
  addAlertLog({ recipient, subject, threat_id, status = 'SENT', error_message = null, details = null }) {
    const stmt = this.db.prepare(`
      INSERT INTO alert_logs (recipient, subject, threat_id, status, error_message, details)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    stmt.run(recipient, subject, threat_id || null, status, error_message, details);
  }

  getRecentAlertLogs(limit = 50) {
    return this.db.prepare('SELECT * FROM alert_logs ORDER BY id DESC LIMIT ?').all(limit);
  }

  // --- Machine Learning & AI Methods ---
  addMLInsight({ ip, attack_probability, anomaly_score, entropy, token_score, velocity_score, classification, model_confidence, payload_snippet, action_taken }) {
    const stmt = this.db.prepare(`
      INSERT INTO ml_insights (ip, attack_probability, anomaly_score, entropy, token_score, velocity_score, classification, model_confidence, payload_snippet, action_taken)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    const res = stmt.run(
      ip,
      attack_probability || 0.0,
      anomaly_score || 0.0,
      entropy || 0.0,
      token_score || 0.0,
      velocity_score || 0.0,
      classification || 'BENIGN',
      model_confidence || 0.0,
      payload_snippet ? payload_snippet.substring(0, 300) : '',
      action_taken || 'Analyzed'
    );
    return Number(res.lastInsertRowid);
  }

  getRecentMLInsights(limit = 50, filterClass = null) {
    let query = 'SELECT * FROM ml_insights';
    const params = [];
    if (filterClass && filterClass !== 'ALL') {
      query += ' WHERE classification = ?';
      params.push(filterClass);
    }
    query += ' ORDER BY id DESC LIMIT ?';
    params.push(limit);
    return this.db.prepare(query).all(...params);
  }

  updateIPReputation(ip, anomalyScore = 0.0, isMalicious = false) {
    const penalty = isMalicious ? 25.0 : (anomalyScore > 0.6 ? 10.0 : 0.0);
    const reward = (anomalyScore < 0.2 && !isMalicious) ? 1.0 : 0.0;

    const stmt = this.db.prepare(`
      INSERT INTO ml_ip_reputation (ip, reputation_score, total_requests, anomaly_count, last_anomaly, last_seen, updated_at)
      VALUES (?, ?, 1, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
      ON CONFLICT(ip) DO UPDATE SET
        reputation_score = MAX(0.0, MIN(100.0, reputation_score - ? + ?)),
        total_requests = total_requests + 1,
        anomaly_count = anomaly_count + (CASE WHEN ? > 0.5 THEN 1 ELSE 0 END),
        last_anomaly = ?,
        last_seen = CURRENT_TIMESTAMP,
        updated_at = CURRENT_TIMESTAMP
    `);
    stmt.run(
      ip,
      Math.max(0.0, 100.0 - penalty),
      anomalyScore > 0.5 ? 1 : 0,
      anomalyScore,
      penalty,
      reward,
      anomalyScore,
      anomalyScore
    );
  }

  getIPReputation(ip) {
    return this.db.prepare('SELECT * FROM ml_ip_reputation WHERE ip = ?').get();
  }

  getTopAnomalousIPs(limit = 15) {
    return this.db.prepare(`
      SELECT * FROM ml_ip_reputation 
      WHERE reputation_score < 70 OR anomaly_count > 0 
      ORDER BY reputation_score ASC, anomaly_count DESC 
      LIMIT ?
    `).all(limit);
  }

  saveModelState(key, valueObj) {
    const stmt = this.db.prepare(`
      INSERT INTO ml_model_state (key, value, updated_at)
      VALUES (?, ?, CURRENT_TIMESTAMP)
      ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP
    `);
    stmt.run(key, JSON.stringify(valueObj));
  }

  getModelState(key) {
    const row = this.db.prepare('SELECT value FROM ml_model_state WHERE key = ?').get();
    if (!row || !row.value) return null;
    try {
      return JSON.parse(row.value);
    } catch (e) {
      return null;
    }
  }

  getMLStats() {
    const totalAnalyzed = this.db.prepare('SELECT COUNT(*) as count FROM ml_insights').get()?.count || 0;
    const totalAnomalies = this.db.prepare("SELECT COUNT(*) as count FROM ml_insights WHERE classification != 'BENIGN'").get()?.count || 0;
    const totalPreemptives = this.db.prepare("SELECT COUNT(*) as count FROM ml_insights WHERE classification = 'PREEMPTIVE_BLOCK'").get()?.count || 0;
    const avgConfidence = this.db.prepare('SELECT AVG(model_confidence) as avg_conf FROM ml_insights').get()?.avg_conf || 0.88;
    const avgEntropy = this.db.prepare('SELECT AVG(entropy) as avg_ent FROM ml_insights').get()?.avg_ent || 3.2;

    const classDistribution = this.db.prepare(`
      SELECT classification, COUNT(*) as count 
      FROM ml_insights 
      GROUP BY classification
    `).all();

    return {
      totalAnalyzed,
      totalAnomalies,
      totalPreemptives,
      accuracyRate: (avgConfidence * 100).toFixed(1),
      avgEntropy: avgEntropy.toFixed(2),
      classDistribution
    };
  }
}

module.exports = new DashSecDB();
