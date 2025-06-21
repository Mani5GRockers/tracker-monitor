<?php
date_default_timezone_set('Asia/Kolkata');
define('DATA_FILE', 'trackers_data.json');

function getCurrentTime() {
    return date('Y-m-d H:i:s');
}

function getResponseTime($host, $port) {
    $start = microtime(true);
    $fp = @fsockopen($host, $port, $errno, $errstr, 2);
    $time = microtime(true) - $start;
    if ($fp) fclose($fp);
    return round($time * 1000);
}

function getHostingProvider($ip) {
    $whois = shell_exec("whois " . escapeshellarg($ip));

    // Match all common fields in order of preference
    preg_match('/descr:\s*(.+)/i', $whois, $descr);
    preg_match('/netname:\s*(.+)/i', $whois, $net);
    preg_match('/org-name:\s*(.+)/i', $whois, $org);
    preg_match('/OrgName:\s*(.+)/i', $whois, $org2);

    return $descr[1] ?? $net[1] ?? $org[1] ?? $org2[1] ?? 'unknown';
}


function getCountryFlag($code) {
    return mb_convert_encoding(
        '&#' . (127397 + ord(strtoupper($code[0]))) . ';&#' . (127397 + ord(strtoupper($code[1]))) . ';',
        'UTF-8',
        'HTML-ENTITIES'
    );
}

function getGeoIP($ip) {
    $ch = curl_init("http://ip-api.com/json/{$ip}?fields=country,countryCode,isp");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5);
    $response = curl_exec($ch);
    curl_close($ch);
    return json_decode($response, true);
}

$trackers = file_exists(DATA_FILE) ? json_decode(file_get_contents(DATA_FILE), true) : [];

if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['trackers'])) {
    $newTrackers = array_filter(array_map('trim', explode("\n", $_POST['trackers'])));
foreach ($newTrackers as $url) {
    $url = trim($url);
    $isValid = preg_match('#^(udp|http|https|wss|ws)://[^/\s:]+(:\d+)?/announce$#i', $url);

if ($isValid && !isset($trackers[$url])) {
    $host = parse_url($url, PHP_URL_HOST);
    $port = parse_url($url, PHP_URL_PORT) ?? 80;
    $ip = @gethostbyname($host);

    if ($ip === $host || !$ip || filter_var($ip, FILTER_VALIDATE_IP) === false) {
        continue;
    }

    // Check if tracker is online before adding
    if (!isOnline($url)) {
        continue; // Skip offline trackers
    }

// Block: localhost or loopback IP
if (
    $ip === '127.0.0.1' || 
    $ip === '127.127.127.127'
) {
    continue; // Skip loopback/fake IP
}


// Block: unknown ISP or country
if (strtolower($isp) === 'unknown' || strtolower($country) === 'unknown') {
    continue; // Skip
}
    $geo = getGeoIP($ip);
    $country = $geo['country'] ?? 'unknown';
    $flag = isset($geo['countryCode']) ? getCountryFlag($geo['countryCode']) : '';
    $isp = $geo['isp'] ?? 'unknown';
// Block specific ISPs like Cloudflare
$blockedISPs = ['cloudflare', 'cloudflarenet', 'cloudflare inc.'];
$normalizedISP = strtolower($isp);

foreach ($blockedISPs as $blocked) {
    if (strpos($normalizedISP, strtolower($blocked)) !== false) {
        continue 2; // Skip this tracker submission
    }
}

    $responseTime = getResponseTime($host, $port);


        $trackers[$url] = [
            'url' => $url,
            'ip' => $ip ?: 'N/A',
            'country' => $country,
            'country_code' => $geo['countryCode'] ?? '', //  Add this line
            'flag' => $flag,
            'isp' => $isp,
            'response_time' => $responseTime,
            'added' => date('d-m-Y'),
            'last_status' => 'Unchecked',
            'last_checked' => 'Never',
            'success' => 0,
            'rank' => 1,
            'fail' => 0
            
        ];
    }
}


    file_put_contents(DATA_FILE, json_encode($trackers, JSON_PRETTY_PRINT));
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}
function isOnline($url) {
    $parts = parse_url($url);
    $host = $parts['host'] ?? '';
    $port = $parts['port'] ?? 80;

    if (stripos($url, 'udp://') === 0) {
        // Attempt DNS resolution
        if (!$host || !checkdnsrr($host, "A")) return false;

        $socket = @stream_socket_client("udp://$host:$port", $errno, $errstr, 2);
        if (!$socket) return false;

        // Send a dummy packet (Connect Request format per BitTorrent UDP spec)
        $packet = pack('N4', 0x417, 0x27101980, 0, random_int(0, PHP_INT_MAX));
        @fwrite($socket, $packet);
        stream_set_timeout($socket, 2);
        $response = @fread($socket, 16);
        fclose($socket);

        return strlen($response) >= 16; // real response
    } else {
        $ch = curl_init($url);
curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'GET');
curl_setopt($ch, CURLOPT_HTTPGET, true);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_TIMEOUT, 5);
curl_setopt($ch, CURLOPT_HEADER, false);
$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);
return ($httpCode >= 200 && $httpCode < 500);
}
}

foreach ($trackers as $url => &$t) {
    $online = isOnline($url);
    $t['last_checked'] = getCurrentTime();
    if ($online) {
        $t['last_status'] = 'Online';
        $t['success']++;
    } else {
        $t['last_status'] = 'Offline';
        $t['fail']++;
    }
}
unset($t);

// Auto remove trackers that are offline for more than 1hrs
foreach ($trackers as $url => $t) {
    if (strtolower($t['last_status']) === 'offline') {
        $lastChecked = DateTime::createFromFormat('Y-m-d H:i:s', $t['last_checked']);
        $now = new DateTime();
        if ($lastChecked && ($now->getTimestamp() - $lastChecked->getTimestamp()) > 3600) {
            unset($trackers[$url]);
        }
    }
}

file_put_contents(DATA_FILE, json_encode($trackers, JSON_PRETTY_PRINT));


function getUptime($s, $f) {
    $total = $s + $f;
    return $total > 0 ? round(($s / $total) * 100, 2) : 0;
}
?>

<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Tracker Rank Monitor</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<!-- Preconnect to favicon service for faster loading -->
<!-- Optional: your page favicon -->
<link rel="icon" href="/favicon.ico" type="image/x-icon">
<link rel="preconnect" href="https://flagcdn.com">
<link rel="preconnect" href="https://ipinfo.io">

    <style>
        body { font-family: sans-serif; background: #eef6ff; padding: 20px; }
        table { width: 100%; border-collapse: collapse; background: #eef6ff; margin-top: 20px; }
        th, td { border: 1px solid #ccc; padding: 8px; font-size: 14px; }
        th { background: #007bff; color: white; }
        .online { color: green; font-weight: bold; }
        .offline { color: red; font-weight: bold; }
        .copy-btn { background: #007bff; color: #fff; padding: 5px; border: none; cursor: pointer; font-size: 12px; }
        .copy-btn:hover { background: #0056b3; }
        textarea { width: 100%; height: 100px; }
        @media (max-width: 768px) {
            table, thead, tbody, th, td, tr { display: block; }
            td { margin-bottom: 10px; }
            
            td.rank { text-align: center; font-weight: bold; }

        }
    </style>
    
    <style>
.gold-row {
    background-color: #fff9c4; /* light gold */
}
.silver-row {
    background-color: #e0e0e0; /* light silver */
}
.bronze-row {
    background-color: #ffe0b2; /* light bronze */
}
</style>

<!-- Style for tracker favicons -->
<style>
    .favicon {
        width: 16px;
        height: 16px;
        vertical-align: middle;
        margin-right: 6px;
    }
</style>

<style>
@media (max-width: 768px) {
    .responsive-bar {
        flex-direction: column;
        align-items: stretch;
        text-align: center;
    }
    .responsive-bar > * {
        flex: unset !important;
        width: 100%;
        margin-bottom: 10px;
    }
    #trackerStats {
        text-align: center !important;
    }
}
</style>


    
    <style>
    nav ul li a:hover {
  text-decoration: underline;
  color: #caffbf;
}

@media (max-width: 768px) {
  nav ul {
    flex-direction: column;
    align-items: center;
  }
  nav ul li {
    margin: 5px 0;
  }
}

    </style>
</head>
<body>




<div style="max-width: 100%; display: flex; justify-content: center;">
  <div style="width: 100%; max-width: 600px;">


<nav style="background-color: #087f23; padding: 10px;">
  <ul style="display: flex; flex-wrap: wrap; list-style: none; margin: 0; padding: 0;">
    <li style="margin: 0 10px;">
      <a href="index.php" style="color: white; text-decoration: none; font-weight: bold;">🏠 Home</a>
    </li>
    <li style="margin: 0 10px;">
      <a href="list.php" style="color: white; text-decoration: none; font-weight: bold;">📄 List</a>
    </li>
    <li style="margin: 0 10px;">
      <a href="submitted.php" style="color: white; text-decoration: none; font-weight: bold;">📥 Submitted</a>
    </li>
    <li style="margin: 0 10px;">
      <a href="faq.php" style="color: white; text-decoration: none; font-weight: bold;">❓ FAQ</a>
    </li>
    <li style="margin: 0 10px;">
      <a href="https://github.com/Mani5GRockers/tracker-monitor" style="color: white; text-decoration: none; font-weight: bold;">📂 Source</a>
    </li>
    <li style="margin: 0 10px;">
      <a href="about.php" style="color: white; text-decoration: none; font-weight: bold;"> About</a>
    </li>
  </ul>
</nav>


    <h2 style="text-align: center;">🌐 Add Torrent Trackers</h2>
       <form method="post" style="background-color: #e6f0ff; padding: 20px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1);">
    <p style="color: #007bff; font-weight: bold; text-align: center; margin-bottom: 10px;">
        ✅ Only <code>udp/http/https/ws/wss</code> URLs ending with <code>/announce</code> are allowed.
    </p> <textarea 
            name="trackers" 
            placeholder="Paste tracker URLs one per line..." 
            style="width: 100%; height: 100px; padding: 10px; border: 2px solid #007bff; border-radius: 6px; font-size: 14px;"></textarea><br><br>
      <div style="text-align: center;">
  <button 
      type="submit" 
      style="background-color: #087f23; color: white; padding: 20px 80px; border: none; border-radius: 10px; cursor: pointer;">
      🚀 Submit Now
  </button>
  
  
</div>

    </form>

  </div>
</div>
<div class="responsive-bar" style="display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 7px; margin: 20px 0;">
    <h3 style="margin: 0; flex: 1;"> Torrent Trackers List</h3>
    <input type="text" id="searchBox" placeholder="Search tracker or country..." onkeyup="filterTable()" 
        style="padding: 6px; flex: 2; min-width: 150px; border: 2px solid #007bff; border-radius: 5px;">
    <div id="trackerStats" style="font-weight: bold; flex: 1; text-align: right;">
        🟢 Online: 0 /  Offline: 0 / 🌐 Total: 0
    </div>
</div>


<table id="trackers">
    <thead>
    <tr>
        <th>Rank</th>
        <th>URL</th>
        <th>IP</th>
        <th>Country</th>
        <th>ISP</th>
        <th>Protocol</th> <!-- New column -->
        <th>Status</th>
        <th>Uptime</th>
        <th>Latency</th>
        <th>Last Checked</th>
        <th>Added</th>
    </tr>
</thead>
    <tbody>

        <?php
        uasort($trackers, function($a, $b) {
            $uptimeA = getUptime($a['success'], $a['fail']);
            $uptimeB = getUptime($b['success'], $b['fail']);
            if ($uptimeA === $uptimeB) {
                return $a['response_time'] <=> $b['response_time'];
            }
            return $uptimeB <=> $uptimeA;
        });

        // Add rank field
$rank = 1;
foreach ($trackers as $url => &$data) {
    $data['rank'] = $rank++;
}
unset($data);
        $rank = 1;
        foreach ($trackers as $t):
    $rowClass = '';
    if ($rank === 1) $rowClass = 'gold-row';
    elseif ($rank === 2) $rowClass = 'silver-row';
    elseif ($rank === 3) $rowClass = 'bronze-row';

            $uptime = getUptime($t['success'], $t['fail']);
        ?>
        
        

<tr class="<?= $rowClass ?>">
   <td style="text-align:center;"><strong>
<?php
if ($rank === 1) echo "🥇";
elseif ($rank === 2) echo "🥈";
elseif ($rank === 3) echo "";
else echo $rank;
$rank++;
?>
</strong></td>


    <td>
        <span class="tracker-url"><?= htmlspecialchars($t['url']) ?></span>
        <button class="copy-btn" onclick="copyToClipboard(this)">Copy</button>
    </td>
    <td><?= $t['ip'] ?></td>
<td>
    <?php if (!empty($t['country_code'])): ?>
       <img loading="lazy" src="https://flagcdn.com/24x18/<?= strtolower($t['country_code']) ?>.png" 
             alt="<?= $t['country'] ?>" 
             style="vertical-align: middle; margin-right: 5px; border:1px solid #ccc; border-radius:2px;" />
    <?php endif; ?>
    <?= $t['country'] ?? 'unknown' ?>
</td>
    <td><?= htmlspecialchars($t['isp'] ?? 'N/A') ?></td>

    <td><strong><?= strtoupper(parse_url($t['url'], PHP_URL_SCHEME)) ?></strong></td> <!-- Protocol -->
    <td class="<?= strtolower($t['last_status']) ?>"><?= $t['last_status'] ?></td>
    <td style="color: <?= $uptime >= 95 ? 'green' : ($uptime >= 50 ? 'orange' : 'red') ?>; font-weight: bold;">
        <?= strtolower($t['last_status']) === 'offline' ? '0%' : $uptime . '%' ?>
    </td>
    <td style="color: <?= $t['response_time'] <= 50 ? 'green' : ($t['response_time'] <= 200 ? 'orange' : 'red') ?>; font-weight: bold;">
        <?= strtolower($t['last_status']) === 'offline' ? 'N/A' : $t['response_time'] . ' ms' ?>
    </td>
    <td><?= $t['last_checked'] ?></td>
    <td><?= $t['added'] ?></td>
</tr>

        <?php endforeach; ?>
    </tbody>
</table>

<center>
<div id="user-info-box" style="
    border: 2px solid #28a745;
    border-radius: 10px;
    padding: 15px;
    background: #f9f9f9;
    margin-top: 30px;
    max-width: 500px;
    box-shadow: 0 0 10px rgba(0,0,0,0.1);
">
  <h3 style="margin-top: 0; color: #28a745;">Your IP & Network Info</h3>
  <p><strong>IP V4 Address:</strong> <span id="ipAddress">Detecting...</span></p>
    <p><strong>Provider:</strong> <span id="provider">Detecting...</span></p>
<p><strong> Country:</strong> <img id="flagIcon" src="" style="height: 16px; vertical-align: middle;" /> <span id="country">Detecting...</span></p>
  <p><strong>State:</strong> <span id="region">Detecting...</span></p>
<p><strong> Browser:</strong> <img id="browserIcon" src="" style="height: 16px; vertical-align: middle;" /> <span id="browserName">Detecting...</span></p>
<p><strong>️ OS:</strong> <img id="osIcon" src="" style="height: 16px; vertical-align: middle;" /> <span id="osName">Detecting...</span></p>
<p><strong>Timezone:</strong> <span id="timezone">Detecting...</span></p>

</div>
</center>
<script src="assets/main.js" defer></script>
</body>
</html>
</html>
