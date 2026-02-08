<?php
header('Content-Type: application/json');
header('Cache-Control: no-cache, must-revalidate');
header('Expires: Mon, 26 Jul 1997 05:00:00 GMT');

// Enable error reporting
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// =====================
// Load GeoIP2
// =====================
require_once '/var/www/html/security/vendor/autoload.php';
use GeoIp2\Database\Reader;

/**
 * Repair common JSON issues
 */
function repairJson($json) {
    // Fix the specific issue: "blocked_total": banned:,
    $json = preg_replace('/"blocked_total":\s*([^,\s\}]+):\s*,/', '"blocked_total": 0,', $json);
    
    // Fix other common issues
    $json = preg_replace('/,\s*}/', '}', $json);
    $json = preg_replace('/,\s*]/', ']', $json);
    
    // Fix single quotes
    $json = preg_replace('/\'/', '"', $json);
    
    return $json;
}

// =====================
// Default Data Structure
// =====================
$response = [
    'failed_total' => 0,
    'blocked_total' => 0,
    'success_total' => 0,
    'top_ips' => [],
    'top_users' => [],
    'banned_list' => '',
    'hourly_failed' => array_fill(0, 24, 0),
    'hourly_blocked' => array_fill(0, 24, 0),
    'date' => date('Y-m-d H:i:s'),
    'status' => 'success',
    'message' => '',
    'json_repaired' => false
];

// =====================
// Load auth_summary.json
// =====================
$file = '/opt/log-monitor/auth_summary.json';

if (!file_exists($file)) {
    $response['status'] = 'error';
    $response['message'] = 'Data file not found';
    echo json_encode($response);
    exit;
}

if (!is_readable($file)) {
    $response['status'] = 'error';
    $response['message'] = 'Data file not readable';
    echo json_encode($response);
    exit;
}

$jsonContent = file_get_contents($file);
if ($jsonContent === false) {
    $response['status'] = 'error';
    $response['message'] = 'Failed to read data file';
    echo json_encode($response);
    exit;
}

// Try to decode JSON
$decoded = json_decode($jsonContent, true);

// If JSON decode fails, try to repair it
if (json_last_error() !== JSON_ERROR_NONE) {
    $repairedJson = repairJson($jsonContent);
    $decoded = json_decode($repairedJson, true);
    
    if (json_last_error() !== JSON_ERROR_NONE) {
        $response['status'] = 'error';
        $response['message'] = 'Invalid JSON format in data file';
        $response['json_error'] = json_last_error_msg();
        echo json_encode($response);
        exit;
    }
    
    $response['json_repaired'] = true;
    $response['message'] = 'JSON data was automatically repaired';
}

if (empty($decoded)) {
    $response['message'] = 'No attack data available';
    echo json_encode($response);
    exit;
}

// Merge decoded data with response
foreach ($decoded as $key => $value) {
    $response[$key] = $value;
}

// Clean and validate numeric fields
$numericFields = ['failed_total', 'blocked_total', 'success_total'];
foreach ($numericFields as $field) {
    if (isset($response[$field])) {
        if (!is_numeric($response[$field])) {
            // Try to extract number from string
            if (preg_match('/(\d+)/', (string)$response[$field], $matches)) {
                $response[$field] = (int)$matches[1];
            } else {
                $response[$field] = 0;
            }
        }
        $response[$field] = intval($response[$field]);
    }
}

// Ensure arrays are arrays
if (!is_array($response['top_ips'])) $response['top_ips'] = [];
if (!is_array($response['top_users'])) $response['top_users'] = [];
if (!is_string($response['banned_list'])) $response['banned_list'] = '';

// =====================
// Add GeoIP Data to IPs
// =====================
$geoDbFile = '/usr/share/GeoIP/GeoLite2-Country.mmdb';
if (file_exists($geoDbFile) && !empty($response['top_ips'])) {
    try {
        $geoReader = new Reader($geoDbFile);
        
        foreach ($response['top_ips'] as &$ipData) {
            try {
                $record = $geoReader->country($ipData['ip']);
                $ipData['country'] = $record->country->name ?? 'Unknown';
                $ipData['country_code'] = strtolower($record->country->isoCode ?? '');
            } catch (Exception $e) {
                $ipData['country'] = 'Unknown';
                $ipData['country_code'] = '';
            }
        }
        unset($ipData);
        
    } catch (Exception $e) {
        // Silently fail
        foreach ($response['top_ips'] as &$ipData) {
            $ipData['country'] = 'Unknown';
            $ipData['country_code'] = '';
        }
        unset($ipData);
    }
} else {
    // Ensure country field exists
    foreach ($response['top_ips'] as &$ipData) {
        $ipData['country'] = 'Unknown';
        $ipData['country_code'] = '';
    }
    unset($ipData);
}

// =====================
// Add Risk Assessment to Users
// =====================
if (!empty($response['top_users'])) {
    foreach ($response['top_users'] as &$userData) {
        $user = $userData['user'] ?? '';
        $count = $userData['count'] ?? 0;
        
        // Determine risk level
        if ($user == 'root') {
            $userData['risk'] = 'high';
            $userData['risk_score'] = 10;
        } elseif (in_array($user, ['admin', 'ubuntu', 'debian', 'centos'])) {
            $userData['risk'] = 'medium';
            $userData['risk_score'] = 7;
        } elseif ($count > 10) {
            $userData['risk'] = 'suspicious';
            $userData['risk_score'] = 5;
        } else {
            $userData['risk'] = 'low';
            $userData['risk_score'] = 2;
        }
    }
    unset($userData);
}

// =====================
// Calculate additional statistics
// =====================
$failedTotal = $response['failed_total'] ?? 0;
$blockedTotal = $response['blocked_total'] ?? 0;
$successTotal = $response['success_total'] ?? 0;

$response['blocked_percentage'] = $failedTotal > 0 ? round(($blockedTotal / $failedTotal) * 100, 1) : 0;
$response['success_percentage'] = $failedTotal > 0 ? round(($successTotal / $failedTotal) * 100, 1) : 0;
$response['attack_rate'] = $successTotal > 0 ? round(($failedTotal / $successTotal), 2) : ($failedTotal > 0 ? $failedTotal : 0);
$response['total_attempts'] = $failedTotal + $successTotal;

// Calculate banned IP count
$bannedCount = 0;
if (!empty($response['banned_list'])) {
    $bannedIps = array_filter(explode(' ', trim($response['banned_list'])));
    $bannedCount = count($bannedIps);
}
$response['banned_count'] = $bannedCount;

// =====================
// Output JSON Response
// =====================
echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
?>