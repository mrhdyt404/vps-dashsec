const nodemailer = require('nodemailer');
const db = require('./database');
const config = require('../config.json');

class AlertNotifier {
  constructor() {
    this.lastAlertTimestamps = new Map(); // ip -> timestamp
    this.minIntervalMs = (config.smtp.min_alert_interval_sec || 30) * 1000;
  }

  getTransporter(smtpSettings = {}) {
    const host = smtpSettings?.host || '127.0.0.1';
    const port = parseInt(smtpSettings?.port, 10) || (smtpSettings?.auth_user ? 587 : 25);
    const secure = Boolean(smtpSettings?.secure) || port === 465;

    // Check if auth credentials are provided
    if (smtpSettings?.auth_user && smtpSettings?.auth_pass) {
      return nodemailer.createTransport({
        host,
        port,
        secure,
        auth: {
          user: smtpSettings.auth_user,
          pass: smtpSettings.auth_pass,
        },
        tls: {
          rejectUnauthorized: false
        },
        connectionTimeout: 10000,
      });
    }

    // Direct / Localhost fallback transport via Postfix
    return nodemailer.createTransport({
      host: (host === 'smtp.gmail.com' && !smtpSettings?.auth_user) ? '127.0.0.1' : host,
      port: (host === 'smtp.gmail.com' && !smtpSettings?.auth_user) ? 25 : port,
      secure: false,
      tls: {
        rejectUnauthorized: false
      },
      connectionTimeout: 10000,
    });
  }

  generateEmailTemplate({
    title,
    status, // 'BREACHED' or 'BLOCKED' or 'TEST'
    severity,
    ip,
    country,
    attackType,
    targetPort,
    service,
    payload,
    ruleName,
    actionTaken,
    timestamp,
    serverIp = config.server.public_ip || '103.179.56.154',
    hostname = config.server.hostname || 'HNTR-VPS'
  }) {
    const isBreach = status === 'BREACHED';
    const statusColor = isBreach ? '#ff003c' : '#00f0ff';
    const statusText = isBreach 
      ? '🚨 PERINGATAN: SERANGAN BERHASIL MASUK / ANCAMAN KRITIS' 
      : '🛡️ LAPORAN: SERANGAN BERHASIL DIBLOKIR SISTEM';

    const statusBadge = isBreach
      ? '<span style="background:#ff003c;color:#fff;padding:5px 12px;border-radius:4px;font-weight:bold;font-size:12px;letter-spacing:1px;">🚨 STATUS: BERHASIL MASUK (BREACH DETECTED)</span>'
      : '<span style="background:#00e599;color:#051510;padding:5px 12px;border-radius:4px;font-weight:bold;font-size:12px;letter-spacing:1px;">🛡️ STATUS: GAGAL / BERHASIL DIBLOKIR (MITIGATED)</span>';

    return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #0b0f19; color: #e2e8f0; margin: 0; padding: 20px; }
    .container { max-width: 650px; margin: 0 auto; background: #131c2e; border: 1px solid #1e293b; border-radius: 12px; overflow: hidden; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
    .header { background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 100%); border-bottom: 2px solid ${statusColor}; padding: 24px; text-align: center; }
    .header h1 { margin: 0 0 10px 0; color: #f8fafc; font-size: 22px; font-weight: 700; letter-spacing: 0.5px; }
    .header p { margin: 0; color: #94a3b8; font-size: 13px; }
    .body { padding: 24px; }
    .alert-banner { background: ${isBreach ? 'rgba(255,0,60,0.15)' : 'rgba(0,240,255,0.1)'}; border: 1px solid ${statusColor}; border-radius: 8px; padding: 15px; margin-bottom: 20px; text-align: center; }
    .table { width: 100%; border-collapse: collapse; margin-bottom: 20px; font-size: 14px; }
    .table td { padding: 10px 12px; border-bottom: 1px solid #1e293b; }
    .table td.label { width: 35%; color: #94a3b8; font-weight: 600; }
    .table td.value { color: #f1f5f9; font-weight: 500; font-family: 'Courier New', monospace; }
    .code-box { background: #080c14; border: 1px solid #2d3748; border-radius: 6px; padding: 12px; font-family: 'Courier New', monospace; font-size: 12px; color: #38bdf8; word-break: break-all; margin-bottom: 20px; max-height: 150px; overflow-y: auto; }
    .actions-box { background: #182235; border-left: 4px solid ${statusColor}; padding: 14px; border-radius: 4px; margin-bottom: 20px; }
    .actions-box h4 { margin: 0 0 8px 0; color: #f8fafc; font-size: 14px; }
    .actions-box ul { margin: 0; padding-left: 20px; font-size: 13px; color: #cbd5e1; }
    .footer { background: #0b101c; border-top: 1px solid #1e293b; padding: 16px; text-align: center; font-size: 12px; color: #64748b; }
    .footer a { color: #38bdf8; text-decoration: none; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>🛡️ DASHSEC SECURITY INCIDENT ALERT</h1>
      <p>Server VPS: <strong>${hostname}</strong> (${serverIp})</p>
    </div>
    <div class="body">
      <div class="alert-banner">
        <div style="margin-bottom:8px;">${statusBadge}</div>
        <div style="font-size: 15px; font-weight: bold; color: ${statusColor};">${title}</div>
      </div>

      <table class="table">
        <tr>
          <td class="label">⏰ Waktu Kejadian</td>
          <td class="value">${timestamp || new Date().toLocaleString('id-ID', { timeZone: 'Asia/Jakarta' })} WIB</td>
        </tr>
        <tr>
          <td class="label">🌐 IP Penyerang</td>
          <td class="value"><span style="color:#f43f5e;font-weight:bold;">${ip}</span> (${country || 'Unknown'})</td>
        </tr>
        <tr>
          <td class="label">🎯 Target Service / Port</td>
          <td class="value">${service} / Port ${targetPort}</td>
        </tr>
        <tr>
          <td class="label">⚡ Vektor Serangan</td>
          <td class="value"><span style="color:#fbbf24;">${attackType}</span></td>
        </tr>
        <tr>
          <td class="label">📋 Rule Terpicu</td>
          <td class="value">${ruleName || 'Security Signature Match'}</td>
        </tr>
        <tr>
          <td class="label">🔥 Tingkat Bahaya (Severity)</td>
          <td class="value"><span style="color:${isBreach ? '#ff003c' : '#fbbf24'};font-weight:bold;">${severity}</span></td>
        </tr>
        <tr>
          <td class="label">🛡️ Tindakan Firewall</td>
          <td class="value">${actionTaken || 'Auto-Blocked via iptables'}</td>
        </tr>
      </table>

      ${payload ? `
      <div style="font-size: 13px; font-weight: 600; color: #94a3b8; margin-bottom: 6px;">🔍 Cuplikan Log / Payload Serangan:</div>
      <div class="code-box">${payload.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</div>
      ` : ''}

      <div class="actions-box">
        <h4>🚨 Rekomendasi Tindakan:</h4>
        <ul>
          ${isBreach ? `
            <li>Segera periksa sesi aktif dan log akses server (${serverIp}).</li>
            <li>Pastikan kredensial SSH / Web admin segera diganti jika ada indikasi kebocoran.</li>
            <li>Gunakan DashSec Dashboard untuk memverifikasi isolasi IP ${ip}.</li>
          ` : `
            <li>IP ${ip} telah diamankan dan diblokir secara otomatis oleh firewall kernel (iptables).</li>
            <li>Tidak ada tindakan mendesak yang diperlukan untuk insiden ini.</li>
          `}
        </ul>
      </div>

      <div style="text-align: center; margin-top: 20px;">
        <a href="http://${serverIp}/dashsec/" style="background: #2563eb; color: #ffffff; padding: 10px 24px; border-radius: 6px; text-decoration: none; font-weight: bold; font-size: 14px; display: inline-block;">Buka Live Dashboard DashSec &rarr;</a>
      </div>
    </div>

    <div class="footer">
      Sistem Pertahanan Otomatis DashSec &bull; Server ${hostname} (${serverIp})<br>
      Notifikasi dikirim secara otomatis melalui protokol SMTP server ke ${config.smtp.recipient_email}
    </div>
  </div>
</body>
</html>
    `;
  }

  async sendAttackAlert({
    threatId = null,
    ip,
    country = 'Unknown',
    attackType,
    targetPort = 80,
    service = 'HTTP',
    payload = '',
    severity = 'HIGH',
    status = 'BLOCKED', // 'BLOCKED' or 'BREACHED'
    ruleName = 'Security Rule',
    actionTaken = 'Blocked by iptables'
  }) {
    const smtpSettings = db.getSMTPSettings() || config.smtp;
    const recipient = smtpSettings.recipient_email || 'mrhxxx7@gmail.com';

    const isBreach = status === 'BREACHED';

    // Check if notification is enabled for this status
    if (isBreach && !smtpSettings.notify_on_breach) {
      console.log('[Notifier] Breach alerts disabled in settings.');
      return;
    }
    if (!isBreach && !smtpSettings.notify_on_block) {
      // User only wants email for breaches, skip sending for standard blocked attacks
      return;
    }

    // Rate limiting: don't spam for same IP within min interval
    const now = Date.now();
    const lastAlert = this.lastAlertTimestamps.get(ip) || 0;
    if (now - lastAlert < this.minIntervalMs && !isBreach) {
      console.log(`[Notifier] Throttling alert for IP ${ip} (last sent ${Math.round((now - lastAlert)/1000)}s ago)`);
      return;
    }
    this.lastAlertTimestamps.set(ip, now);

    const subject = isBreach
      ? `🚨 [CRITICAL BREACH] Serangan Berhasil Masuk di Server VPS ${config.server.hostname} (${ip})`
      : `🛡️ [DEFENDED] Serangan ${attackType} Berhasil Diblokir di Server VPS (${ip})`;

    const htmlContent = this.generateEmailTemplate({
      title: isBreach ? `Deteksi Serangan Berhasil Masuk (${attackType})` : `Serangan ${attackType} Berhasil Digagalkan`,
      status,
      severity,
      ip,
      country,
      attackType,
      targetPort,
      service,
      payload,
      ruleName,
      actionTaken,
      timestamp: new Date().toLocaleString('id-ID', { timeZone: 'Asia/Jakarta' })
    });

    try {
      const transporter = this.getTransporter(smtpSettings);
      const mailOptions = {
        from: `"${smtpSettings.sender_name || 'DashSec Defense'}" <${smtpSettings.sender_email || 'dashsec@hntr.local'}>`,
        to: recipient,
        subject,
        html: htmlContent,
        text: `[DashSec Alert] Status: ${status} | Vector: ${attackType} | Attacker IP: ${ip} (${country}) | Target: ${service}:${targetPort} | Action: ${actionTaken} | Details: ${payload}`
      };

      console.log(`[Notifier] Dispatching SMTP alert to ${recipient} (Status: ${status})...`);
      
      const info = await transporter.sendMail(mailOptions);
      console.log(`[Notifier] ✅ Email sent successfully! MessageId: ${info.messageId}`);

      db.addAlertLog({
        recipient,
        subject,
        threat_id: threatId,
        status: 'SENT',
        error_message: null,
        details: `MessageId: ${info.messageId}`
      });

      return { success: true, messageId: info.messageId };
    } catch (err) {
      console.error(`[Notifier] ❌ Failed to send SMTP alert:`, err.message);

      db.addAlertLog({
        recipient,
        subject,
        threat_id: threatId,
        status: 'FAILED',
        error_message: err.message,
        details: err.stack
      });

      return { success: false, error: err.message };
    }
  }

  async sendTestEmail(customSettings = null) {
    let smtpSettings = customSettings;
    if (!smtpSettings || !smtpSettings.host) {
      smtpSettings = db.getSMTPSettings() || config.smtp;
    }
    if (!smtpSettings) {
      smtpSettings = {
        host: '127.0.0.1',
        port: 25,
        secure: false,
        sender_email: 'dashsec-alert@hntr.local',
        sender_name: 'DashSec VPS Defense',
        recipient_email: 'mrhxxx7@gmail.com'
      };
    }
    const recipient = smtpSettings.recipient_email || 'mrhxxx7@gmail.com';

    const subject = `🧪 [TEST ALERT] Uji Coba Pengiriman Notifikasi SMTP DashSec VPS`;
    const htmlContent = this.generateEmailTemplate({
      title: 'Uji Coba Notifikasi Protokol SMTP DashSec Berhasil!',
      status: 'BLOCKED',
      severity: 'LOW',
      ip: '203.0.113.199',
      country: 'Indonesia (Test Mode)',
      attackType: 'SIMULATED_TEST_VECTOR',
      targetPort: 443,
      service: 'HTTPS-WAF',
      payload: "TEST PAYLOAD: SELECT * FROM admin WHERE '1'='1' (Simulated Defense Verification)",
      ruleName: 'DashSec-SMTP-Verification-Rule',
      actionTaken: 'Simulated Auto-Block & Alert Dispatch Verified',
      timestamp: new Date().toLocaleString('id-ID', { timeZone: 'Asia/Jakarta' })
    });

    try {
      const transporter = this.getTransporter(smtpSettings);
      const info = await transporter.sendMail({
        from: `"${smtpSettings.sender_name || 'DashSec Defense'}" <${smtpSettings.sender_email || 'dashsec@hntr.local'}>`,
        to: recipient,
        subject,
        html: htmlContent,
        text: `Uji coba sistem notifikasi SMTP DashSec berhasil dikirim ke ${recipient}.`
      });

      db.addAlertLog({
        recipient,
        subject,
        threat_id: null,
        status: 'SENT',
        details: `Test Email Success: ${info.messageId}`
      });

      return { success: true, message: `Email uji coba berhasil dikirim ke ${recipient}!`, messageId: info.messageId };
    } catch (err) {
      db.addAlertLog({
        recipient,
        subject,
        threat_id: null,
        status: 'FAILED',
        error_message: err.message
      });

      return { success: false, error: err.message };
    }
  }
}

module.exports = new AlertNotifier();
