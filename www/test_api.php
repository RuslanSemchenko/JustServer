<?php
/**
 * REST API Test Endpoint for JustServer
 * Tests JSON API handling through FastCGI
 */

header('Content-Type: application/json');
header('X-Powered-By: JustServer/1.0');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

// Handle CORS preflight
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$path = $_SERVER['REQUEST_URI'] ?? '/';

$response = [
    'server' => 'JustServer/1.0',
    'php_version' => PHP_VERSION,
    'method' => $method,
    'path' => $path,
    'timestamp' => microtime(true),
    'headers' => [],
];

// Collect request headers
foreach ($_SERVER as $key => $value) {
    if (str_starts_with($key, 'HTTP_')) {
        $header_name = str_replace('_', '-', substr($key, 5));
        $response['headers'][$header_name] = $value;
    }
}

switch ($method) {
    case 'GET':
        $response['data'] = [
            'message' => 'API is working',
            'query_params' => $_GET,
            'memory_usage' => memory_get_usage(true),
            'pid' => getmypid(),
        ];
        break;

    case 'POST':
        $input = file_get_contents('php://input');
        $parsed = json_decode($input, true);
        $response['data'] = [
            'received' => $parsed ?? $input,
            'content_length' => strlen($input),
            'content_type' => $_SERVER['CONTENT_TYPE'] ?? 'unknown',
        ];
        break;

    default:
        http_response_code(405);
        $response['error'] = 'Method not allowed';
        break;
}

echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
