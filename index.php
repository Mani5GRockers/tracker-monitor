<?php
date_default_timezone_set('Asia/Kolkata');
define('DATA_FILE', 'trackers_data.json');

function getCurrentTime() {
    return date('Y-m-d h:i:s A');
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
    if (preg_match('/^OrgName:\s*(.+)$/mi', $whois, $match)) {
        return trim($match[1]);
    }
    return 'Unknown';
}


function getCountryFlag($code) {
    return mb_convert_encoding(
        '&#' . (127397 + ord(strtoupper($code[0]))) . ';&#' . (127397 + ord(strtoupper($code[1]))) . ';',
        'UTF-8',
        'HTML-ENTITIES'
    );
}

function getGeoIP($ip) {
    $ch = curl_init("http://ip-api.com/json/{$ip}?fields=country,countryCode");
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
        if (!isset($trackers[$url]) && (filter_var($url, FILTER_VALIDATE_URL) || stripos($url, 'udp://') === 0)) {
            $host = parse_url($url, PHP_URL_HOST);
$ip = @gethostbyname($host);
if ($ip === $host || !$ip || filter_var($ip, FILTER_VALIDATE_IP) === false) {
    continue; // Skip if IP is invalid or unresolved
}
            $geo = getGeoIP($ip);
            $country = $geo['country'] ?? 'Unknown';
            $flag = isset($geo['countryCode']) ? getCountryFlag($geo['countryCode']) : '🌍';
            $provider = getHostingProvider($ip);
            $responseTime = getResponseTime($host, parse_url($url, PHP_URL_PORT) ?? 80);
            $trackers[$url] = [
                'url' => $url,
                'ip' => $ip ?: 'N/A',
                'country' => $country,
                'flag' => $flag,
                'provider' => $provider,
                'response_time' => $responseTime,
                'added' => date('d-m-Y'),
                'last_status' => 'Unchecked',
                'last_checked' => 'Never',
                'success' => 0,
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
        curl_setopt($ch, CURLOPT_NOBODY, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 5);
        curl_exec($ch);
        $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_errno($ch);
        curl_close($ch);
        return ($error === 0 && $status >= 200 && $status < 400);
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
    <style>
        body { font-family: sans-serif; background: #f7f7f7; padding: 20px; }
        table { width: 100%; border-collapse: collapse; background: #fff; margin-top: 20px; }
        th, td { border: 1px solid #ccc; padding: 8px; font-size: 14px; }
        th { background: #333; color: white; }
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
</head>
<body>

<h2>🌐 Add Torrent Trackers</h2>
<form method="post">
    <textarea name="trackers" placeholder="Paste tracker URLs one per line..."></textarea><br>
    <button type="submit">Add Trackers</button>
</form>

<div id="topTrackersBox" style="
    border: 2px solid #007bff;
    border-radius: 10px;
    padding: 15px;
    background: #eef6ff;
    margin-top: 20px;
    max-width: 600px;
    box-shadow: 0 0 10px rgba(0,0,0,0.1);
">
  <h3 style="margin-top: 0; color: #007bff;">🏆 Top 3 Reliable & Fast Trackers</h3>
  <ol id="topTrackersList">
    <li>Loading...</li>
  </ol>
</div>


<h3>🌍 World Top Ranked Torrent Trackers 📈 </h3>
<input type="text" id="searchBox" placeholder="Search tracker or country..." onkeyup="filterTable()" style="margin-bottom:10px;padding:6px;width:50%;">


<div id="trackerStats" style="font-weight:bold; margin-top: 10px;">
  Loading tracker stats...
</div>

<table id="trackers">
    <thead>
    <tr>
        <th>Rank</th>
        <th>URL</th>
        <th>IP</th>
        <th>Country</th>
        <th>Provider</th>
        <th>Protocol</th> <!-- New column -->
        <th>Status</th>
        <th>Uptime %</th>
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
        $rank = 1;
        foreach ($trackers as $t):
            $uptime = getUptime($t['success'], $t['fail']);
        ?>
        
        

<tr>
    <td style="text-align:center;"><strong>
    <?php
    if ($rank === 1) echo "🥇";
    elseif ($rank === 2) echo "🥈";
    elseif ($rank === 3) echo "🥉";
    else echo $rank;
    $rank++;
    ?>
    </strong></td>

    <td>
        <span class="tracker-url"><?= htmlspecialchars($t['url']) ?></span>
        <button class="copy-btn" onclick="copyToClipboard(this)">Copy</button>
    </td>
    <td><?= $t['ip'] ?></td>
    <td><?= $t['flag'] . ' ' . $t['country'] ?></td>
    <td><?= $t['provider'] ?></td>
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
  <p><strong>IP Address:</strong> <span id="ipAddress">Detecting...</span></p>
  <p><strong>Country:</strong> <span id="country">Detecting...</span></p>
  <p><strong>Provider:</strong> <span id="provider">Detecting...</span></p>
  <p><strong>Network:</strong> <span id="network">Detecting...</span></p>
</div>
</center>

<script>
function updateTopTrackers() {
    fetch('best.php')
        .then(res => res.json())
        .then(data => {
            const list = document.getElementById('topTrackersList');
            list.innerHTML = '';
            data.forEach(t => {
                const li = document.createElement('li');
                li.innerHTML = `<code>${t.url}</code><br>🔁 Uptime: ${t.uptime}% | ⚡ Latency: ${t.latency} ms`;
                list.appendChild(li);
            });
        })
        .catch(() => {
            document.getElementById('topTrackersList').innerHTML = '<li>Unable to load top trackers.</li>';
        });
}

updateTopTrackers();
setInterval(updateTopTrackers, 20000); // refresh every 20 sec

</script>
<script>

function updateTrackerStats() {
    fetch('tracker_summary.php')
        .then(res => res.json())
        .then(data => {
            document.getElementById('trackerStats').innerHTML =
                `✅ Live trackers: ${data.live} / ❌ Trackers down: ${data.down} / 🌐 Total trackers: ${data.total}`;
        })
        .catch(() => {
            document.getElementById('trackerStats').innerText = "Failed to load tracker stats.";
        });
}

updateTrackerStats(); // first load
setInterval(updateTrackerStats, 15000); // auto-refresh every 15 sec
</script>

<script>
function filterByProtocol() {
    const selected = document.getElementById("protocolFilter").value;
    const rows = document.querySelectorAll("#tracker-table tbody tr");
    rows.forEach(row => {
        const protocol = row.children[2].textContent.trim().toUpperCase();
        if (selected === "ALL" || protocol === selected) {
            row.style.display = "";
        } else {
            row.style.display = "none";
        }
    });
}

</script>

<script>
function copyToClipboard(btn) {
    const text = btn.parentElement.querySelector(".tracker-url").textContent;
    navigator.clipboard.writeText(text).then(() => {
        btn.innerText = "Copied!";
        setTimeout(() => btn.innerText = "Copy", 1000);
    });
}

function filterTable() {
    let q = document.getElementById("searchBox").value.toLowerCase();
    let rows = document.querySelectorAll("#trackers tbody tr");
    rows.forEach(row => {
        let url = row.querySelector("td:nth-child(2)")?.innerText.toLowerCase();
        let country = row.querySelector("td:nth-child(4)")?.innerText.toLowerCase();
        row.style.display = (url.includes(q) || country.includes(q)) ? "" : "none";
    });
}

fetch("https://ipinfo.io/json?token=324708c6bee796")
  .then(res => res.json())
  .then(data => {
      document.getElementById("ipAddress").textContent = data.ip || "N/A";
      document.getElementById("country").textContent = data.country || "N/A";
      document.getElementById("provider").textContent = data.org || "N/A";
      document.getElementById("network").textContent = data.hostname || "N/A";
  }).catch(() => {
      document.getElementById("ipAddress").textContent = "N/A";
  });
</script>

</body>
</html>
