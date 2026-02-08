<?php
// =====================
// Initialize GeoIP2
// =====================
require_once '/var/www/html/security/vendor/autoload.php';
use GeoIp2\Database\Reader;

$geoReader = null;
$geoDbFile = '/usr/share/GeoIP/GeoLite2-Country.mmdb';
if(file_exists($geoDbFile)){
    try {
        $geoReader = new Reader($geoDbFile);
    } catch(Exception $e) {
        // Silently fail if GeoIP database is not available
        $geoReader = null;
    }
}

// =====================
// Load Dashboard Data
// =====================
$data = null;
$message = null;
$file = '/opt/log-monitor/auth_summary.json';

if (!is_readable($file)) {
    $message = 'Data log belum tersedia. Pastikan file /opt/log-monitor/auth_summary.json ada dan dapat dibaca.';
} else {
    $jsonContent = file_get_contents($file);
    if ($jsonContent === false) {
        $message = 'Gagal membaca data log. Periksa izin file.';
    } else {
        $decoded = json_decode($jsonContent, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            $message = 'Format data log rusak. Periksa struktur JSON.';
        } elseif (empty($decoded)) {
            $message = 'Belum ada aktivitas serangan yang tercatat.';
        } else {
            $data = $decoded;
            // Ensure required fields exist
            $defaults = [
                'failed_total' => 0,
                'blocked_total' => 0,
                'success_total' => 0,
                'top_ips' => [],
                'top_users' => [],
                'date' => date('Y-m-d H:i:s')
            ];
            $data = array_merge($defaults, $data);
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VPS Security - SSH Monitor</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<style>
:root {
    --bg-dark: #1e1e2f;
    --bg-light: #f5f5f5;
    --text-primary: #ffffff;
    --text-secondary: #aaaaaa;
    --accent-red: #e74c3c;
    --accent-green: #2ecc71;
    --accent-yellow: #f1c40f;
    --accent-blue: #3498db;
    --bg-card: #2a2a3d;
    --bg-header: #1e1e2f;
}
* {
    box-sizing: border-box;
}
body {
    margin: 0;
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background: var(--bg-dark);
    color: var(--text-primary);
    line-height: 1.6;
}
.container { 
    max-width: 1200px; 
    margin: 0 auto; 
    padding: 20px; 
}
.header { 
    display: flex; 
    justify-content: space-between; 
    align-items: center; 
    margin-bottom: 20px; 
    flex-wrap: wrap;
}
.logo h1 { 
    margin:0; 
    font-size: 24px; 
    color: var(--accent-blue);
}
.logo p { 
    margin:5px 0 0; 
    color: var(--text-secondary); 
    font-size:14px; 
}
.status-indicator {
    background: var(--bg-card);
    padding: 8px 15px;
    border-radius: 20px;
    font-size: 14px;
}
.stats-container { 
    display:flex; 
    gap:20px; 
    flex-wrap:wrap; 
    margin-bottom:20px; 
}
.stat-card { 
    background: var(--bg-card);
    flex:1 1 200px; 
    padding:20px; 
    border-radius:10px; 
    position:relative;
    transition: transform 0.3s ease;
}
.stat-card:hover {
    transform: translateY(-5px);
}
.stat-header { 
    display:flex; 
    justify-content:space-between; 
    align-items:center; 
    margin-bottom:10px; 
}
.stat-value { 
    font-size:32px; 
    font-weight:bold; 
    margin-bottom:5px;
}
.stat-label { 
    font-size:14px; 
    color: var(--text-secondary); 
}
.stat-icon i { 
    font-size:28px; 
}
.stat-icon.danger i { color: var(--accent-red); }
.stat-icon.success i { color: var(--accent-green); }
.stat-icon.warning i { color: var(--accent-yellow); }
.stat-trend { 
    font-size:12px; 
    color: var(--text-secondary); 
    display:flex; 
    align-items:center; 
    gap:5px; 
    margin-top:10px;
}
.badge { 
    padding:3px 10px; 
    border-radius:12px; 
    color:#fff; 
    font-size:11px; 
    font-weight:600;
    display: inline-block;
}
.badge-high { background: var(--accent-red); }
.badge-medium { background: var(--accent-yellow); color: #333; }
.badge-low { background: var(--accent-blue); }
.badge-success { background: var(--accent-green); }
.table-container { 
    display:flex; 
    gap:20px; 
    flex-wrap:wrap; 
    margin-top: 30px;
}
.table-card { 
    flex:1 1 500px; 
    background: var(--bg-card); 
    border-radius:10px; 
    overflow:hidden;
    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
}
.table-card .table-header {
    padding:15px; 
    background: var(--bg-header);
    font-weight: 600;
    display: flex;
    align-items: center;
    gap: 10px;
}
.table-card table { 
    width:100%; 
    border-collapse:collapse; 
}
.table-card th, .table-card td { 
    padding:12px 15px; 
    text-align:left; 
    border-bottom:1px solid rgba(255,255,255,0.1); 
}
.table-card th { 
    background: rgba(30, 30, 47, 0.5); 
    font-weight: 600;
    color: var(--accent-blue);
}
.table-card tr:hover {
    background: rgba(255,255,255,0.05);
}
.footer { 
    margin-top:40px; 
    padding-top:20px;
    display:flex; 
    justify-content:space-between; 
    align-items:center; 
    font-size:12px; 
    color:var(--text-secondary);
    border-top: 1px solid rgba(255,255,255,0.1);
}

/* Loading and Message Styles */
.loading {
    text-align: center;
    padding: 60px 20px;
    color: var(--text-secondary);
    font-size: 16px;
}
.loading i {
    font-size: 24px;
    margin-bottom: 10px;
    display: block;
}
.info-message {
    background: var(--accent-blue);
    color: white;
    padding: 20px;
    border-radius: 10px;
    margin: 20px 0;
    text-align: center;
}
.info-message i {
    font-size: 24px;
    margin-bottom: 10px;
    display: block;
}
.error-message {
    background: var(--accent-red);
    color: white;
    padding: 20px;
    border-radius: 10px;
    margin: 20px 0;
    text-align: center;
}
.troubleshoot {
    margin-top: 15px;
    font-size: 12px;
    background: rgba(0,0,0,0.2);
    padding: 10px;
    border-radius: 5px;
    text-align: left;
}
.troubleshoot code {
    background: rgba(0,0,0,0.3);
    padding: 2px 6px;
    border-radius: 3px;
    font-family: monospace;
}

/* Chart Container */
.chart-container {
    background: var(--bg-card);
    padding: 20px;
    border-radius: 10px;
    margin-top: 20px;
    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
}

/* Responsive Design */
@media (max-width: 768px) {
    .header {
        flex-direction: column;
        align-items: flex-start;
        gap: 10px;
    }
    .stats-container {
        gap: 10px;
    }
    .stat-card {
        flex: 1 1 100%;
    }
    .table-card {
        flex: 1 1 100%;
    }
    .footer {
        flex-direction: column;
        gap: 10px;
        text-align: center;
    }
}
</style>
</head>
<body>
<div class="container">
    <header class="header">
        <div class="logo">
            <h1><i class="fas fa-shield-alt"></i> VPS Security Dashboard</h1>
            <p>SSH Monitoring & Threat Detection</p>
        </div>
        <div class="status-indicator">
            <span><i class="fas fa-circle" style="color:var(--accent-green); margin-right: 5px;"></i> Live Monitoring</span>
        </div>
    </header>

    <?php if($message): ?>
        <div class="info-message">
            <i class="fas fa-info-circle"></i> <?= htmlspecialchars($message) ?>
            <div class="troubleshoot">
                <strong>Troubleshooting:</strong><br>
                1. Cek apakah service log-monitor berjalan:<br>
                <code>sudo systemctl status log-monitor</code><br><br>
                2. Cek izin file auth_summary.json:<br>
                <code>ls -la /opt/log-monitor/auth_summary.json</code><br><br>
                3. Restart service jika diperlukan:<br>
                <code>sudo systemctl restart log-monitor</code>
            </div>
        </div>
    <?php elseif(empty($data)): ?>
        <div class="loading">
            <i class="fas fa-spinner fa-spin"></i>
            <div>Loading security data...</div>
        </div>
    <?php else: ?>
    
    <!-- STAT CARDS -->
    <div class="stats-container">
        <div class="stat-card">
            <div class="stat-header">
                <div>
                    <div class="stat-value"><?= htmlspecialchars($data['failed_total']) ?></div>
                    <div class="stat-label">Failed SSH Attempts</div>
                </div>
                <div class="stat-icon danger"><i class="fas fa-exclamation-triangle"></i></div>
            </div>
            <div class="stat-trend">
                <i class="fas fa-arrow-up" style="color:var(--accent-red)"></i> Potential Threats Detected
            </div>
        </div>

        <div class="stat-card">
            <div class="stat-header">
                <div>
                    <div class="stat-value"><?= htmlspecialchars($data['blocked_total']) ?></div>
                    <div class="stat-label">Blocked Attempts</div>
                </div>
                <div class="stat-icon success"><i class="fas fa-shield-check"></i></div>
            </div>
            <div class="stat-trend">
                <?php 
                $blockedPercentage = isset($data['failed_total']) && $data['failed_total'] > 0 
                    ? round(($data['blocked_total'] / $data['failed_total']) * 100, 1) 
                    : 0;
                ?>
                <i class="fas fa-chart-line" style="color:var(--accent-green)"></i> 
                <?= $blockedPercentage ?>% of threats blocked
            </div>
        </div>

        <div class="stat-card">
            <div class="stat-header">
                <div>
                    <div class="stat-value"><?= htmlspecialchars($data['success_total']) ?></div>
                    <div class="stat-label">Successful Logins</div>
                </div>
                <div class="stat-icon warning"><i class="fas fa-user-check"></i></div>
            </div>
            <div class="stat-trend">
                <?php 
                $successPercentage = isset($data['failed_total']) && $data['failed_total'] > 0 
                    ? round(($data['success_total'] / $data['failed_total']) * 100, 1) 
                    : 0;
                ?>
                <i class="fas fa-chart-pie" style="color:var(--accent-yellow)"></i> 
                <?= $successPercentage ?>% success rate
            </div>
        </div>
    </div>

    <!-- CHART -->
    <div class="chart-container">
        <canvas id="sshChart" height="150"></canvas>
    </div>

    <!-- TABLES -->
    <div class="table-container">
        <!-- Top IPs -->
        <div class="table-card">
            <div class="table-header">
                <i class="fas fa-network-wired"></i> Top IP Attackers
            </div>
            <table>
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Attempts</th>
                        <th>Threat Level</th>
                        <th>Country</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if(!empty($data['top_ips'])): ?>
                        <?php foreach($data['top_ips'] as $i=>$ip): ?>
                        <tr>
                            <td>
                                <i class="fas fa-globe" style="margin-right: 5px; color: var(--accent-blue);"></i>
                                <?= htmlspecialchars($ip['ip']) ?>
                            </td>
                            <td><strong><?= $ip['count'] ?></strong></td>
                            <td>
                                <?php 
                                $cls = 'badge-low';
                                $txt = 'Low';
                                if($ip['count'] > 30) {
                                    $cls = 'badge-high';
                                    $txt = 'High';
                                } elseif($ip['count'] > 15) {
                                    $cls = 'badge-medium';
                                    $txt = 'Medium';
                                }
                                ?>
                                <span class="badge <?= $cls ?>">
                                    <i class="fas fa-<?= $cls === 'badge-high' ? 'skull' : ($cls === 'badge-medium' ? 'exclamation-triangle' : 'info-circle') ?>"></i>
                                    <?= $txt ?>
                                </span>
                            </td>
                            <td>
                                <?php
                                $country = 'Unknown';
                                $countryCode = '';
                                if($geoReader){
                                    try {
                                        $record = $geoReader->country($ip['ip']);
                                        $country = $record->country->name ?? 'Unknown';
                                        $countryCode = strtolower($record->country->isoCode ?? '');
                                    } catch(Exception $e){
                                        $country = 'Unknown';
                                    }
                                }
                                ?>
                                <?php if($countryCode): ?>
                                    <i class="fas fa-flag"></i> 
                                <?php endif; ?>
                                <?= htmlspecialchars($country) ?>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <tr>
                            <td colspan="4" style="text-align:center; padding: 30px; color: var(--text-secondary);">
                                <i class="fas fa-check-circle" style="font-size: 24px; margin-bottom: 10px; display: block; color: var(--accent-green);"></i>
                                No suspicious IP activity detected
                            </td>
                        </tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>

        <!-- Top Users -->
        <div class="table-card">
            <div class="table-header">
                <i class="fas fa-user-ninja"></i> Targeted Users
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Username</th>
                        <th>Attempts</th>
                        <th>Risk Level</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if(!empty($data['top_users'])): ?>
                        <?php foreach($data['top_users'] as $user): ?>
                        <tr>
                            <td>
                                <i class="fas fa-user" style="margin-right: 5px; color: var(--accent-blue);"></i>
                                <?= htmlspecialchars($user['user']) ?>
                            </td>
                            <td><strong><?= $user['count'] ?></strong></td>
                            <td>
                                <?php 
                                $cls = 'badge-low';
                                $txt = 'Low Risk';
                                $icon = 'user';
                                
                                if($user['user'] == 'root') {
                                    $cls = 'badge-high';
                                    $txt = 'High Risk';
                                    $icon = 'crown';
                                } elseif(in_array($user['user'], ['admin', 'ubuntu', 'debian'])) {
                                    $cls = 'badge-medium';
                                    $txt = 'Medium Risk';
                                    $icon = 'exclamation-triangle';
                                } elseif($user['count'] > 10) {
                                    $cls = 'badge-medium';
                                    $txt = 'Suspicious';
                                    $icon = 'user-secret';
                                }
                                ?>
                                <span class="badge <?= $cls ?>">
                                    <i class="fas fa-<?= $icon ?>"></i>
                                    <?= $txt ?>
                                </span>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <tr>
                            <td colspan="3" style="text-align:center; padding: 30px; color: var(--text-secondary);">
                                <i class="fas fa-user-shield" style="font-size: 24px; margin-bottom: 10px; display: block; color: var(--accent-green);"></i>
                                No user attack patterns detected
                            </td>
                        </tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>

    <footer class="footer">
        <div>
            <i class="fas fa-clock" style="margin-right: 5px;"></i>
            Last update: <?= htmlspecialchars($data['date']) ?>
        </div>
        <div>
            <i class="fas fa-server" style="margin-right: 5px;"></i>
            VPS Security Dashboard v2.2 | Real-time Monitoring Active
        </div>
    </footer>

    <?php endif; ?>
</div>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script>
// Initialize Chart
const ctx = document.getElementById('sshChart').getContext('2d');
const sshChart = new Chart(ctx, {
    type: 'line',
    data: {
        labels: Array.from({length: 24}, (_, h) => h.toString().padStart(2, '0') + ":00"),
        datasets: [
            {
                label: 'Failed Attempts',
                data: Array(24).fill(0),
                borderColor: '#e74c3c',
                backgroundColor: 'rgba(231, 76, 60, 0.1)',
                borderWidth: 2,
                fill: true,
                tension: 0.4,
                pointBackgroundColor: '#e74c3c',
                pointRadius: 4
            },
            {
                label: 'Blocked Attempts',
                data: Array(24).fill(0),
                borderColor: '#2ecc71',
                backgroundColor: 'rgba(46, 204, 113, 0.1)',
                borderWidth: 2,
                fill: true,
                tension: 0.4,
                pointBackgroundColor: '#2ecc71',
                pointRadius: 4
            }
        ]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                position: 'top',
                labels: {
                    color: '#ffffff',
                    font: {
                        size: 12
                    }
                }
            },
            tooltip: {
                mode: 'index',
                intersect: false,
                backgroundColor: 'rgba(0, 0, 0, 0.8)'
            }
        },
        scales: {
            x: {
                grid: {
                    color: 'rgba(255, 255, 255, 0.1)'
                },
                ticks: {
                    color: '#aaaaaa',
                    maxTicksLimit: 12
                }
            },
            y: {
                beginAtZero: true,
                grid: {
                    color: 'rgba(255, 255, 255, 0.1)'
                },
                ticks: {
                    color: '#aaaaaa'
                }
            }
        }
    }
});

// Create update indicator
const updateIndicator = document.createElement('div');
updateIndicator.id = 'updateIndicator';
updateIndicator.style.cssText = `
    position: fixed;
    bottom: 20px;
    right: 20px;
    background: #2a2a3d;
    padding: 10px 15px;
    border-radius: 8px;
    font-size: 12px;
    z-index: 1000;
    border: 1px solid #3498db;
    box-shadow: 0 4px 6px rgba(0,0,0,0.3);
    display: flex;
    align-items: center;
    gap: 8px;
`;

// Update dashboard function
async function updateDashboard() {
    try {
        const updateTime = document.getElementById('lastUpdateTime');
        if (updateTime) {
            updateTime.innerHTML = `<i class="fas fa-sync fa-spin"></i> Updating...`;
        }
        
        const res = await fetch('data.php?_=' + new Date().getTime());
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        
        const data = await res.json();
        
        // Update stat cards
        const failedTotal = data.failed_total ?? 0;
        const blockedTotal = data.blocked_total ?? 0;
        const successTotal = data.success_total ?? 0;
        
        document.querySelector('.stat-card:nth-child(1) .stat-value').textContent = failedTotal;
        document.querySelector('.stat-card:nth-child(2) .stat-value').textContent = blockedTotal;
        document.querySelector('.stat-card:nth-child(3) .stat-value').textContent = successTotal;
        
        // Update percentages
        const blockedPercentage = failedTotal > 0 ? ((blockedTotal / failedTotal) * 100).toFixed(1) : 0;
        const successPercentage = failedTotal > 0 ? ((successTotal / failedTotal) * 100).toFixed(1) : 0;
        
        document.querySelector('.stat-card:nth-child(2) .stat-trend').innerHTML = 
            `<i class="fas fa-chart-line" style="color:var(--accent-green)"></i> ${blockedPercentage}% of threats blocked`;
        
        document.querySelector('.stat-card:nth-child(3) .stat-trend').innerHTML = 
            `<i class="fas fa-chart-pie" style="color:var(--accent-yellow)"></i> ${successPercentage}% success rate`;
        
        // Update top IPs table
        const tbodyIPs = document.querySelector('.table-card:nth-child(1) tbody');
        if (data.top_ips && data.top_ips.length) {
            let html = '';
            data.top_ips.forEach(ip => {
                let cls = 'badge-low', txt = 'Low', icon = 'info-circle';
                if (ip.count > 30) {
                    cls = 'badge-high';
                    txt = 'High';
                    icon = 'skull';
                } else if (ip.count > 15) {
                    cls = 'badge-medium';
                    txt = 'Medium';
                    icon = 'exclamation-triangle';
                }
                
                html += `<tr>
                    <td><i class="fas fa-globe" style="margin-right: 5px; color: var(--accent-blue);"></i> ${ip.ip}</td>
                    <td><strong>${ip.count}</strong></td>
                    <td><span class="badge ${cls}"><i class="fas fa-${icon}"></i> ${txt}</span></td>
                    <td><i class="fas fa-flag"></i> ${ip.country || 'Unknown'}</td>
                </tr>`;
            });
            tbodyIPs.innerHTML = html;
        } else {
            tbodyIPs.innerHTML = `<tr><td colspan="4" style="text-align:center; padding: 30px; color: var(--text-secondary);">
                <i class="fas fa-check-circle" style="font-size: 24px; margin-bottom: 10px; display: block; color: var(--accent-green);"></i>
                No suspicious IP activity detected
            </td></tr>`;
        }
        
        // Update top users table
        const tbodyUsers = document.querySelector('.table-card:nth-child(2) tbody');
        if (data.top_users && data.top_users.length) {
            let html = '';
            data.top_users.forEach(user => {
                let cls = 'badge-low', txt = 'Low Risk', icon = 'user';
                
                if (user.user == 'root') {
                    cls = 'badge-high';
                    txt = 'High Risk';
                    icon = 'crown';
                } else if (['admin', 'ubuntu', 'debian'].includes(user.user)) {
                    cls = 'badge-medium';
                    txt = 'Medium Risk';
                    icon = 'exclamation-triangle';
                } else if (user.count > 10) {
                    cls = 'badge-medium';
                    txt = 'Suspicious';
                    icon = 'user-secret';
                }
                
                html += `<tr>
                    <td><i class="fas fa-user" style="margin-right: 5px; color: var(--accent-blue);"></i> ${user.user}</td>
                    <td><strong>${user.count}</strong></td>
                    <td><span class="badge ${cls}"><i class="fas fa-${icon}"></i> ${txt}</span></td>
                </tr>`;
            });
            tbodyUsers.innerHTML = html;
        } else {
            tbodyUsers.innerHTML = `<tr><td colspan="3" style="text-align:center; padding: 30px; color: var(--text-secondary);">
                <i class="fas fa-user-shield" style="font-size: 24px; margin-bottom: 10px; display: block; color: var(--accent-green);"></i>
                No user attack patterns detected
            </td></tr>`;
        }
        
        // Update chart if data exists
        if (data.hourly_failed && data.hourly_blocked) {
            sshChart.data.datasets[0].data = data.hourly_failed;
            sshChart.data.datasets[1].data = data.hourly_blocked;
            sshChart.update('none');
        }
        
        // Update footer date
        const footerDate = document.querySelector('.footer div:first-child');
        if (footerDate && data.date) {
            footerDate.innerHTML = `<i class="fas fa-clock" style="margin-right: 5px;"></i>
            Last update: ${new Date().toLocaleTimeString()}`;
        }
        
        // Update indicator
        updateIndicator.innerHTML = `
            <i class="fas fa-check-circle" style="color:#2ecc71"></i>
            <div>
                <div>Last update: ${new Date().toLocaleTimeString()}</div>
                <div style="font-size:10px; color:#aaaaaa">Auto-refresh: 5s</div>
            </div>
        `;
        
    } catch (e) {
        console.error('Error fetching dashboard data:', e);
        updateIndicator.innerHTML = `
            <i class="fas fa-exclamation-triangle" style="color:#e74c3c"></i>
            <div>
                <div>Update failed</div>
                <div style="font-size:10px; color:#aaaaaa">${e.message}</div>
            </div>
        `;
    }
}

// Initialize and start auto-refresh
document.body.appendChild(updateIndicator);
updateDashboard(); // Initial load
setInterval(updateDashboard, 5000); // Update every 5 seconds
</script>
</body>
</html>