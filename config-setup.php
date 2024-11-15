<?php
// config.php

// Environment setting
define('ENVIRONMENT', 'production'); // Change to 'development' for testing

// Database configuration
define('DB_HOST', '192.168.5.61');
define('DB_USERNAME', 'Alex R.');
define('DB_PASSWORD', 'PasswordPassword');
define('DB_NAME', 'test1');
define('DB_CHARSET', 'utf8mb4');

// Security configuration
define('HASH_ALGO', PASSWORD_ARGON2ID);
define('HASH_OPTIONS', [
    'memory_cost' => 65536,  // 64MB
    'time_cost' => 4,        // 4 iterations
    'threads' => 3           // 3 parallel threads
]);

// Session configuration
define('SESSION_LIFETIME', 3600); // 1 hour
define('SESSION_NAME', 'secure_session');
define('COOKIE_SECURE', true);
define('COOKIE_HTTPONLY', true);
define('COOKIE_SAMESITE', 'Strict');

// Rate limiting
define('RATE_LIMIT_MAX_ATTEMPTS', 5);
define('RATE_LIMIT_TIMEFRAME', 3600); // 1 hour
define('RATE_LIMIT_BLOCKTIME', 86400); // 24 hours

// Email verification
define('EMAIL_VERIFICATION_EXPIRY', 86400); // 24 hours
define('PASSWORD_RESET_EXPIRY', 3600); // 1 hour

// Logging configuration
define('LOG_DIR', __DIR__ . '/logs');
define('ERROR_LOG_FILE', LOG_DIR . '/error.log');
define('ACCESS_LOG_FILE', LOG_DIR . '/access.log');
define('AUDIT_LOG_FILE', LOG_DIR . '/audit.log');

// Security headers
$security_headers = [
    'Strict-Transport-Security' => 'max-age=31536000; includeSubDomains; preload',
    'X-Content-Type-Options' => 'nosniff',
    'X-Frame-Options' => 'SAMEORIGIN',
    'X-XSS-Protection' => '1; mode=block',
    'Content-Security-Policy' => "default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; img-src 'self' data:; font-src 'self'; form-action 'self'; frame-ancestors 'none';",
    'Permissions-Policy' => 'geolocation=(), microphone=(), camera=()',
    'Referrer-Policy' => 'strict-origin-when-cross-origin'
];

// Apply security headers
foreach ($security_headers as $header => $value) {
    header("$header: $value");
}

// Error handling based on environment
if (ENVIRONMENT === 'development') {
    error_reporting(E_ALL);
    ini_set('display_errors', 1);
} else {
    error_reporting(E_ALL);
    ini_set('display_errors', 0);
    ini_set('log_errors', 1);
    ini_set('error_log', ERROR_LOG_FILE);
}

// Ensure secure session settings
ini_set('session.cookie_secure', COOKIE_SECURE);
ini_set('session.cookie_httponly', COOKIE_HTTPONLY);
ini_set('session.cookie_samesite', COOKIE_SAMESITE);
ini_set('session.gc_maxlifetime', SESSION_LIFETIME);
ini_set('session.use_strict_mode', 1);
ini_set('session.use_only_cookies', 1);
ini_set('session.name', SESSION_NAME);

// Create logging directory if it doesn't exist
if (!is_dir(LOG_DIR)) {
    mkdir(LOG_DIR, 0755, true);
}

// Database connection function
function getDBConnection() {
    try {
        $dsn = "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=" . DB_CHARSET;
        $options = [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
            PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES " . DB_CHARSET . " COLLATE utf8mb4_unicode_ci"
        ];
        
        return new PDO($dsn, DB_USERNAME, DB_PASSWORD, $options);
    } catch (PDOException $e) {
        error_log("Database connection failed: " . $e->getMessage());
        throw new Exception("Database connection failed");
    }
}
