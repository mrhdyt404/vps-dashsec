const { execSync, exec } = require('node:child_process');
const db = require('./database');
const config = require('../config.json');

const CHAIN_NAME = 'DASHSEC_IPS';

class FirewallManager {
  constructor() {
    this.whitelist = new Set(config.whitelist || []);
    this.initFirewall();
    this.syncWhitelist();
  }

  runCmd(command) {
    try {
      return execSync(`sudo ${command}`, { encoding: 'utf8', timeout: 5000 }).trim();
    } catch (err) {
      // Return error message if any
      return null;
    }
  }

  initFirewall() {
    console.log('[Firewall] Initializing iptables DASHSEC_IPS chain...');
    try {
      // 1. Check if DASHSEC_IPS chain exists, if not create it
      const chains = this.runCmd('iptables -N ' + CHAIN_NAME);
    } catch (e) {
      // Chain might already exist
    }

    try {
      // 2. Check if DASHSEC_IPS is hooked into INPUT chain
      const checkHook = this.runCmd(`iptables -C INPUT -j ${CHAIN_NAME}`);
    } catch (e) {
      // Not hooked, hook it at position 1
      this.runCmd(`iptables -I INPUT 1 -j ${CHAIN_NAME}`);
      console.log('[Firewall] Hooked DASHSEC_IPS into top of INPUT chain');
    }

    // Sync database whitelist with initial config
    for (const ip of (config.whitelist || [])) {
      db.addWhitelistedIP(ip, 'Default Whitelist');
    }

    // Sync active bans from DB to iptables
    this.syncBansFromDB();

    // Start background expired ban cleaner every 60 seconds
    setInterval(() => this.checkExpiredBans(), 60000);
  }

  syncWhitelist() {
    const list = db.getWhitelistedIPs();
    this.whitelist = new Set(list.map(item => item.ip));
    for (const ip of (config.whitelist || [])) {
      this.whitelist.add(ip);
    }
  }

  isWhitelisted(ip) {
    if (!ip) return true;
    if (ip === '127.0.0.1' || ip === '::1' || ip === 'localhost') return true;
    this.syncWhitelist();
    if (this.whitelist.has(ip)) return true;

    // Check CIDR / Subnet matches
    for (const item of this.whitelist) {
      if (item.includes('/') && this.ipInSubnet(ip, item)) {
        return true;
      }
    }
    return false;
  }

  ipInSubnet(ip, cidr) {
    try {
      const [range, bits = 32] = cidr.split('/');
      const mask = ~(2 ** (32 - bits) - 1);
      const ipNum = ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
      const rangeNum = range.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
      return (ipNum & mask) === (rangeNum & mask);
    } catch (e) {
      return false;
    }
  }

  isAlreadyBannedInIptables(ip) {
    try {
      const output = this.runCmd(`iptables -C ${CHAIN_NAME} -s ${ip} -j DROP`);
      return true;
    } catch (e) {
      return false;
    }
  }

  blockIP({ ip, reason = 'Automated Threat Mitigation', threat_score = 100, duration_hours = 24, manual = 0, country = 'Unknown', country_code = 'UN' }) {
    if (!ip || this.isWhitelisted(ip)) {
      console.log(`[Firewall] Skip blocking whitelisted/invalid IP: ${ip}`);
      return { success: false, reason: 'IP is whitelisted or invalid' };
    }

    // Check if already in iptables to avoid duplicate rules
    if (!this.isAlreadyBannedInIptables(ip)) {
      console.log(`[Firewall] 🚨 BLOCKING IP: ${ip} | Reason: ${reason} | Score: ${threat_score}`);
      try {
        this.runCmd(`iptables -I ${CHAIN_NAME} 1 -s ${ip} -j DROP`);
      } catch (err) {
        console.error(`[Firewall] Error inserting iptables drop for ${ip}:`, err.message);
      }
    }

    // Record or update in SQLite DB
    db.addBlockedIP({
      ip,
      reason,
      threat_score,
      duration_hours,
      manual,
      country,
      country_code
    });

    return { success: true, ip, reason, duration_hours };
  }

  unblockIP(ip) {
    if (!ip) return { success: false };
    console.log(`[Firewall] Unblocking IP: ${ip}`);

    // Remove from iptables (loop in case of multiple rules)
    let removed = true;
    let attempts = 0;
    while (removed && attempts < 5) {
      try {
        const res = this.runCmd(`iptables -D ${CHAIN_NAME} -s ${ip} -j DROP`);
        if (res === null) break;
        attempts++;
      } catch (e) {
        removed = false;
      }
    }

    // Update DB
    db.unblockIP(ip);
    return { success: true, ip };
  }

  syncBansFromDB() {
    const activeBans = db.getActiveBlockedIPs();
    console.log(`[Firewall] Syncing ${activeBans.length} active bans from DB to iptables...`);
    for (const ban of activeBans) {
      try {
        // Test if already in iptables
        this.runCmd(`iptables -C ${CHAIN_NAME} -s ${ban.ip} -j DROP`);
      } catch (e) {
        // Not in iptables, add it
        this.runCmd(`iptables -I ${CHAIN_NAME} 1 -s ${ban.ip} -j DROP`);
      }
    }
  }

  checkExpiredBans() {
    const expired = db.getExpiredBans();
    if (expired.length > 0) {
      console.log(`[Firewall] Found ${expired.length} expired bans. Unblocking...`);
      for (const item of expired) {
        this.unblockIP(item.ip);
      }
    }
  }

  flushAll() {
    try {
      this.runCmd(`iptables -F ${CHAIN_NAME}`);
      const active = db.getActiveBlockedIPs();
      for (const b of active) {
        db.unblockIP(b.ip);
      }
      return { success: true, message: 'All firewall rules flushed' };
    } catch (err) {
      return { success: false, error: err.message };
    }
  }

  getFirewallStatus() {
    try {
      const iptablesRules = this.runCmd(`iptables -L ${CHAIN_NAME} -n -v --line-numbers`) || '';
      const activeBans = db.getActiveBlockedIPs();
      return {
        chain: CHAIN_NAME,
        active_bans_count: activeBans.length,
        raw_iptables: iptablesRules,
        whitelist_count: this.whitelist.size
      };
    } catch (err) {
      return { chain: CHAIN_NAME, error: err.message };
    }
  }
}

module.exports = new FirewallManager();
