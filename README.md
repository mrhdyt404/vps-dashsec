# 🛡️ DashSec VPS Defense — Real-Time Intrusion Prevention & Live SOC Monitoring

**DashSec** adalah sistem keamanan cerdas untuk server VPS berbasis Linux yang memantau ancaman serangan secara *real-time* (SSH Brute Force, Web WAF, SQL Injection, XSS, Path Traversal, Scanners, DoS Bursts, dan Intrusion Breach), melakukan pemblokiran otomatis (*Auto-Block*) pada level kernel firewall Linux (`iptables`), menyediakan **Live Dashboard Monitoring** modern dengan WebSocket, serta mengirimkan notifikasi log serangan & alert email via protokol SMTP ke email tujuan jika terdeteksi ancaman kritis/serangan berhasil masuk (*breach*).

---

## ✨ Fitur Utama

- **Real-Time Threat Detection Engine**:
  - **SSH Protection**: Memantau `/var/log/auth.log` secara *real-time* untuk mendeteksi brute force password, invalid user, dan preauth flood. Mendeteksi login SSH sukses dari IP publik asing sebagai status **🚨 CRITICAL BREACH**.
  - **Web Application Firewall (WAF)**: Menganalisis log Apache (`*_access.log`) untuk mendeteksi SQL Injection, XSS, Path Traversal / LFI (`/etc/passwd`), bot vulnerability scanners (`sqlmap`, `nikto`, `nuclei`, `gobuster`), serta probe file sensitif (`.env`, `.git`, `wp-config.php`, webshells).
  - **Attack Status Classifier**: Mengklasifikasikan status serangan menjadi:
    - `🛡️ BLOCKED / DEFENDED`: Serangan berhasil digagalkan dan diblokir oleh firewall.
    - `🚨 BREACH / INTRUSION`: Serangan berhasil mengakses resource sensitif (HTTP 200) atau unauthorized SSH login.
    - `⚠️ MONITORED`: Aktivitas mencurigakan dalam ambang batas pemantauan.

- **Automated Kernel Firewall (iptables)**:
  - Mengelola *dedicated netfilter chain* `DASHSEC_IPS` di baris teratas `INPUT` chain pada `iptables` (*line-rate kernel DROP*).
  - **Auto-Unban Scheduler**: Membuka blokir IP secara otomatis sesuai masa berlaku (*configurable* default 24 jam).
  - **Whitelist Protection**: Melindungi IP localhost, subnet privat, dan IP admin agar tidak pernah terblokir secara tidak sengaja.
  - **1-Click Manual Control**: Blokir dan buka blokir IP langsung melalui Dashboard.

- **Live SOC Dashboard Monitoring**:
  - Tampilan Dark Cyber SOC modern dengan glassmorphism, Google Fonts (*Outfit* & *JetBrains Mono*), dan Chart.js visualisasi.
  - Streaming event real-time melalui WebSocket tanpa reload halaman.
  - Kartu KPI: Total Serangan, IP Terblokir, Tingkat Keberhasilan Mitigasi, Insiden Breach, dan Telemetri VPS (CPU, RAM, Uptime).
  - Filter interaktif (All, Blocked, Breached, Monitored) dan pencarian instan.
  - Web Audio alert synthesizers untuk bunyi notifikasi ancaman baru.

- **Sistem Notifikasi Email SMTP**:
  - Terintegrasi langsung dengan protokol SMTP (Postfix lokal port 25 & opsi SMTP eksternal seperti Gmail port 587).
  - Mengirimkan email berformat HTML profesional dengan profil penyerang, geo location, signature payload, status insiden, dan rekomendasi mitigasi.
  - Dilengkapi fitur *Test SMTP Alert* langsung dari web UI.

- **Security Threat Simulator**:
  - Panel simulator interaktif untuk menguji respons sistem terhadap serangan SSH, SQLi, LFI, dan pengiriman email alert darurat secara *live*.

---

## 🚀 Instalasi & Menjalankan Sistem

### 1. Kebutuhan Sistem
- Linux VPS (Debian / Ubuntu / Rocky / AlmaLinux)
- Node.js v18+ atau v20+ / v22+
- `iptables` & `sudo` privileges
- Apache2 / Nginx (Opsional sebagai Reverse Proxy)
- Postfix / MTA (Opsional untuk SMTP lokal)

### 2. Setup Dependensi
```bash
cd /var/www/html/dashsec
npm install
```

### 3. Konfigurasi
Edit berkas `config.json` sesuai kebutuhan server:
```json
{
  "server": {
    "port": 8443,
    "public_ip": "YOUR_SERVER_IP",
    "hostname": "YOUR_HOSTNAME"
  },
  "whitelist": [
    "127.0.0.1",
    "::1",
    "YOUR_ADMIN_IP"
  ],
  "smtp": {
    "enabled": true,
    "host": "smtp.gmail.com",
    "port": 587,
    "recipient_email": "mrhxxx7@gmail.com"
  }
}
```

### 4. Menjalankan Layanan Latar Belakang (Systemd)
Buat berkas layanan `/etc/systemd/system/dashsec.service`:
```ini
[Unit]
Description=DashSec VPS Intrusion Prevention & Live SOC Dashboard
After=network.target apache2.service

[Service]
Type=simple
User=root
WorkingDirectory=/var/www/html/dashsec
ExecStart=/usr/bin/node /var/www/html/dashsec/server.js
Restart=always
RestartSec=3
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
```

Aktifkan dan jalankan:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now dashsec.service
```

---

## 🌐 Akses Web Dashboard

Buka peramban (browser) dan akses:
- **Port Standar Web**: `http://YOUR_SERVER_IP/dashsec/`
- **Port Langsung**: `http://YOUR_SERVER_IP:8443/`

---

## 📁 Struktur Berkas

```
/var/www/html/dashsec/
├── config.json          # Konfigurasi server, whitelist, SMTP & threshold deteksi
├── server.js            # Express API & WebSocket Real-Time Server
├── package.json         # Dependensi Node.js (express, ws, nodemailer)
├── engine/
│   ├── database.js      # SQLite Database Manager (threat logs, bans, alerts)
│   ├── detector.js      # Multi-vector threat detector & log tailer
│   ├── firewall.js      # iptables controller & whitelist engine
│   └── notifier.js      # SMTP mailer & cyber alert HTML formatter
└── public/
    ├── index.html       # Antarmuka Dashboard SOC
    ├── css/
    │   └── dashboard.css# Styling Dark Cyber Modern Theme (Vanilla CSS)
    └── js/
        └── app.js       # Logika interaktif frontend & WebSocket client
```

---

## 📜 Lisensi

Didistribusikan di bawah lisensi MIT. Bebas digunakan dan dikembangkan untuk keamanan server VPS.
