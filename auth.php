<?php
declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, private');
header('X-Content-Type-Options: nosniff');

function respond(array $payload, int $status = 200): never
{
    http_response_code($status);
    echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

$method = $_SERVER['REQUEST_METHOD'] ?? '';
if ($method !== 'GET' && $method !== 'POST') {
    header('Allow: GET, POST');
    respond(['error' => 'Método no permitido.'], 405);
}

$authFile = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR)
    . DIRECTORY_SEPARATOR . 'whatsapp-unincca-auth-' . hash('sha256', __DIR__) . '.json';
$lockHandle = @fopen($authFile . '.lock', 'c');
if ($lockHandle === false || !flock($lockHandle, LOCK_EX)) {
    respond(['error' => 'No se pudo acceder al almacenamiento de autenticación.'], 500);
}

$stored = null;
if (is_file($authFile)) {
    $decoded = json_decode((string) @file_get_contents($authFile), true);
    if (is_array($decoded) && isset($decoded['hash']) && is_string($decoded['hash'])) {
        $stored = $decoded['hash'];
    }
}

if ($method === 'GET') {
    respond(['configured' => $stored !== null]);
}

$request = json_decode((string) file_get_contents('php://input'), true);
if (!is_array($request) || !isset($request['action'], $request['password']) || !is_string($request['password'])) {
    respond(['error' => 'Solicitud inválida.'], 400);
}

$action = $request['action'];
$password = $request['password'];

if ($action === 'setup') {
    if ($stored !== null) {
        respond(['configured' => true, 'error' => 'La clave ya está configurada.'], 409);
    }
    if (strlen($password) < 4) {
        respond(['error' => 'La clave debe tener al menos 4 caracteres.'], 422);
    }

    $temporaryFile = $authFile . '.' . bin2hex(random_bytes(8)) . '.tmp';
    $contents = json_encode(['hash' => password_hash($password, PASSWORD_DEFAULT)]);
    if (file_put_contents($temporaryFile, $contents, LOCK_EX) === false || !rename($temporaryFile, $authFile)) {
        @unlink($temporaryFile);
        respond(['error' => 'No se pudo guardar la clave en el servidor.'], 500);
    }
    @chmod($authFile, 0600);
    respond(['configured' => true]);
}

if ($action === 'verify') {
    if ($stored === null) {
        respond(['configured' => false, 'error' => 'Primero debes crear la clave.'], 409);
    }
    if (!password_verify($password, $stored)) {
        respond(['error' => 'Clave incorrecta.'], 401);
    }
    respond(['configured' => true]);
}

respond(['error' => 'Acción no válida.'], 400);