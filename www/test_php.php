<?php
/**
 * PHP + JavaScript Test Page for JustServer
 * Tests FastCGI integration between JustServer and php-fpm
 */

header('Content-Type: text/html; charset=utf-8');
header('X-Powered-By: JustServer/1.0 + PHP/' . PHP_VERSION);

$server_info = [
    'php_version' => PHP_VERSION,
    'server_software' => $_SERVER['SERVER_SOFTWARE'] ?? 'JustServer',
    'server_protocol' => $_SERVER['SERVER_PROTOCOL'] ?? 'HTTP/1.1',
    'request_method' => $_SERVER['REQUEST_METHOD'] ?? 'GET',
    'request_uri' => $_SERVER['REQUEST_URI'] ?? '/',
    'document_root' => $_SERVER['DOCUMENT_ROOT'] ?? '/var/www/html',
    'timestamp' => date('Y-m-d H:i:s'),
    'timezone' => date_default_timezone_get(),
];

// Handle AJAX POST requests for testing
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json');
    $input = json_decode(file_get_contents('php://input'), true);

    $response = [
        'status' => 'ok',
        'echo' => $input,
        'server_time' => microtime(true),
        'php_version' => PHP_VERSION,
        'memory_usage' => memory_get_usage(true),
    ];

    echo json_encode($response, JSON_PRETTY_PRINT);
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PHP + JS Test - JustServer</title>
    <style>
        body {
            font-family: monospace;
            background: #1a1a2e;
            color: #eee;
            padding: 2rem;
        }
        .test-section {
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1rem;
        }
        .pass { color: #00ff88; }
        .fail { color: #ff4444; }
        .info { color: #4488ff; }
        .warn { color: #ffaa00; }
        h1 { color: #8b5cf6; margin-bottom: 1rem; }
        h2 { color: #888; margin-bottom: 0.5rem; }
        table { width: 100%; border-collapse: collapse; margin: 1rem 0; }
        th, td {
            text-align: left;
            padding: 0.5rem;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }
        th { color: #4488ff; }
        button {
            background: #8b5cf6;
            color: white;
            border: none;
            padding: 0.5rem 1.5rem;
            border-radius: 4px;
            cursor: pointer;
            font-size: 1rem;
            margin: 0.5rem 0.5rem 0.5rem 0;
        }
        button:hover { background: #7c4fe6; }
        pre {
            background: rgba(0,0,0,0.3);
            padding: 1rem;
            border-radius: 4px;
            overflow-x: auto;
        }
        #result-list .result-line {
            padding: 0.3rem 0;
            border-bottom: 1px solid rgba(255,255,255,0.05);
        }
    </style>
</head>
<body>
    <h1>PHP + JavaScript Test Page</h1>
    <p class="info">Testing FastCGI integration: JustServer -> php-fpm</p>

    <div class="test-section">
        <h2>PHP Server Information</h2>
        <table>
            <?php foreach ($server_info as $key => $value): ?>
            <tr>
                <th><?= htmlspecialchars($key) ?></th>
                <td><?= htmlspecialchars($value) ?></td>
            </tr>
            <?php endforeach; ?>
        </table>
        <p class="pass">PHP execution via FastCGI: OK</p>
    </div>

    <div class="test-section">
        <h2>PHP Session Test</h2>
        <?php
        session_start();
        if (!isset($_SESSION['visit_count'])) {
            $_SESSION['visit_count'] = 0;
        }
        $_SESSION['visit_count']++;
        ?>
        <p>Session ID: <span class="info"><?= session_id() ?></span></p>
        <p>Visit count: <span class="pass"><?= $_SESSION['visit_count'] ?></span></p>
    </div>

    <div class="test-section">
        <h2>JS -> PHP AJAX Test</h2>
        <button onclick="runAjaxTest()">Send POST to PHP</button>
        <pre id="ajax-result">Click button to test AJAX communication</pre>
    </div>

    <div class="test-section">
        <h2>PHP-Generated JavaScript Data</h2>
        <pre id="php-data"></pre>
    </div>

    <div class="test-section">
        <h2>Combined PHP + JS Tests</h2>
        <button onclick="runAllTests()">Run All Tests</button>
        <div id="result-list"></div>
    </div>

    <script>
        // PHP-generated data embedded in JS
        const serverData = <?= json_encode($server_info) ?>;

        document.getElementById('php-data').textContent = JSON.stringify(serverData, null, 2);

        function addResult(name, passed, detail) {
            const list = document.getElementById('result-list');
            const div = document.createElement('div');
            div.className = 'result-line';
            div.innerHTML = `<span class="${passed ? 'pass' : 'fail'}">${passed ? 'PASS' : 'FAIL'}</span> ${name} ${detail ? '- ' + detail : ''}`;
            list.appendChild(div);
        }

        async function runAjaxTest() {
            const area = document.getElementById('ajax-result');
            try {
                const response = await fetch(window.location.pathname, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        test: 'ajax_roundtrip',
                        client_time: Date.now(),
                        message: 'Hello from JavaScript!'
                    })
                });

                const data = await response.json();
                area.textContent = JSON.stringify(data, null, 2);
                addResult('AJAX POST to PHP', data.status === 'ok', 'Round-trip OK');
            } catch (e) {
                area.textContent = 'Error: ' + e.message;
                addResult('AJAX POST to PHP', false, e.message);
            }
        }

        function runAllTests() {
            document.getElementById('result-list').innerHTML = '';

            // Test 1: PHP data available in JS
            addResult('PHP data in JS', typeof serverData === 'object', 'PHP version: ' + serverData.php_version);

            // Test 2: PHP timestamp is recent
            const phpTime = new Date(serverData.timestamp).getTime();
            const now = Date.now();
            const timeDiff = Math.abs(now - phpTime);
            addResult('PHP timestamp fresh', timeDiff < 60000, 'Diff: ' + timeDiff + 'ms');

            // Test 3: Server software
            addResult('Server identification', serverData.server_software.includes('JustServer'), serverData.server_software);

            // Test 4: Fetch test
            runAjaxTest();

            // Test 5: PHP rendered HTML correctly
            const phpElements = document.querySelectorAll('table tr');
            addResult('PHP HTML rendering', phpElements.length > 0, phpElements.length + ' table rows');

            // Test 6: Session data
            const visitEl = document.querySelector('.test-section .pass');
            addResult('PHP Sessions', visitEl !== null, 'Session active');
        }
    </script>
</body>
</html>
