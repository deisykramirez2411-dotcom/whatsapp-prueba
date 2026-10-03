<?php
declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, private');
header('X-Content-Type-Options: nosniff');

$https = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== '' && $_SERVER['HTTPS'] !== 'off';
session_name('whatsapp_unincca_session');
ini_set('session.use_strict_mode', '1');
ini_set('session.gc_maxlifetime', (string) (60 * 60 * 24 * 30));
session_set_cookie_params([
    'lifetime' => 60 * 60 * 24 * 30,
    'path' => '/',
    'secure' => $https,
    'httponly' => true,
    'samesite' => 'Lax',
]);
session_start();

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

$documentRoot = realpath($_SERVER['DOCUMENT_ROOT'] ?? '') ?: dirname(__DIR__);
$storageDir = getenv('WHATSAPP_AUTH_DIR');
if ($storageDir === false || trim($storageDir) === '') {
    $storageDir = dirname($documentRoot) . DIRECTORY_SEPARATOR . '.whatsapp-unincca-auth';
}
if (!is_dir($storageDir) && !@mkdir($storageDir, 0700, true) && !is_dir($storageDir)) {
    respond(['error' => 'No se pudo crear el almacenamiento privado de autenticación.'], 500);
}
@chmod($storageDir, 0700);

$instancePath = realpath(__DIR__) ?: __DIR__;
$authFile = rtrim($storageDir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . hash('sha256', $instancePath) . '.json';
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
    respond([
        'configured' => $stored !== null,
        'authenticated' => $stored !== null && ($_SESSION['authenticated'] ?? false) === true,
    ]);
}

$request = json_decode((string) file_get_contents('php://input'), true);
if (!is_array($request) || !isset($request['action']) || !is_string($request['action'])) {
    respond(['error' => 'Solicitud inválida.'], 400);
}

$action = $request['action'];

if ($action === 'logout') {
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $cookie = session_get_cookie_params();
        setcookie(session_name(), '', [
            'expires' => time() - 42000,
            'path' => $cookie['path'],
            'domain' => $cookie['domain'],
            'secure' => $cookie['secure'],
            'httponly' => $cookie['httponly'],
            'samesite' => $cookie['samesite'],
        ]);
    }
    session_destroy();
    respond(['authenticated' => false]);
}

if ($action === 'setup') {
    if (!isset($request['password']) || !is_string($request['password'])) {
        respond(['error' => 'Solicitud inválida.'], 400);
    }
    $password = $request['password'];
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
    session_regenerate_id(true);
    $_SESSION['authenticated'] = true;
    respond(['configured' => true, 'authenticated' => true]);
}

if ($action === 'verify') {
    if (!isset($request['password']) || !is_string($request['password'])) {
        respond(['error' => 'Solicitud inválida.'], 400);
    }
    $password = $request['password'];
    if ($stored === null) {
        respond(['configured' => false, 'error' => 'Primero debes crear la clave.'], 409);
    }
    if (!password_verify($password, $stored)) {
        respond(['error' => 'Clave incorrecta.'], 401);
    }
    session_regenerate_id(true);
    $_SESSION['authenticated'] = true;
    respond(['configured' => true, 'authenticated' => true]);
}

if ($action === 'change-password') {
    if (($_SESSION['authenticated'] ?? false) !== true) {
        respond(['error' => 'La sesión expiró. Ingresa nuevamente.'], 401);
    }
    if (!isset($request['currentPassword'], $request['newPassword'])
        || !is_string($request['currentPassword'])
        || !is_string($request['newPassword'])) {
        respond(['error' => 'Solicitud inválida.'], 400);
    }
    if (!password_verify($request['currentPassword'], $stored ?? '')) {
        respond(['error' => 'La contraseña actual es incorrecta.'], 401);
    }
    if (strlen($request['newPassword']) < 4) {
        respond(['error' => 'La nueva contraseña debe tener al menos 4 caracteres.'], 422);
    }

    $temporaryFile = $authFile . '.' . bin2hex(random_bytes(8)) . '.tmp';
    $contents = json_encode(['hash' => password_hash($request['newPassword'], PASSWORD_DEFAULT)]);
    if (file_put_contents($temporaryFile, $contents, LOCK_EX) === false || !rename($temporaryFile, $authFile)) {
        @unlink($temporaryFile);
        respond(['error' => 'No se pudo guardar la nueva contraseña en el servidor.'], 500);
    }
    @chmod($authFile, 0600);
    session_regenerate_id(true);
    respond(['configured' => true, 'authenticated' => true]);
}

respond(['error' => 'Acción no válida.'], 400);