<?php
// register.php
require_once 'config.php';

class RegistrationHandler {
    private $pdo;
    private $response = [
        'success' => false,
        'message' => '',
        'errors' => []
    ];

    public function __construct() {
        try {
            $this->pdo = getDBConnection();
            $this->initializeSession();
        } catch (Exception $e) {
            $this->logError('Database connection failed', $e);
            $this->response['errors'][] = 'Service temporarily unavailable';
            $this->sendResponse();
        }
    }

    private function initializeSession() {
        if (session_status() === PHP_SESSION_NONE) {
            session_set_cookie_params([
                'lifetime' => SESSION_LIFETIME,
                'path' => '/',
                'secure' => COOKIE_SECURE,
                'httponly' => COOKIE_HTTPONLY,
                'samesite' => COOKIE_SAMESITE
            ]);
            session_start();
        }
    }

    public function handleRegistration() {
        try {
            if (!$this->validateRequest()) {
                return;
            }

            if (!$this->checkRateLimit()) {
                return;
            }

            $userData = $this->sanitizeInput();
            if (!$this->validateInput($userData)) {
                return;
            }

            if (!$this->isUniqueUser($userData)) {
                return;
            }

            $this->createUser($userData);
            
        } catch (Exception $e) {
            $this->logError('Registration failed', $e);
            $this->response['errors'][] = 'Registration failed. Please try again later.';
        }

        $this->sendResponse();
    }

    private function validateRequest(): bool {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            $this->response['errors'][] = 'Invalid request method';
            return false;
        }

        if (!isset($_SESSION['csrf_token']) || !isset($_POST['csrf_token']) || 
            !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
            $this->response['errors'][] = 'Invalid request';
            $this->logSecurityEvent('CSRF token validation failed');
            return false;
        }

        return true;
    }

    private function checkRateLimit(): bool {
        $ip = $this->getClientIP();
        
        $stmt = $this->pdo->prepare("
            SELECT attempts, last_attempt, blocked_until 
            FROM rate_limits 
            WHERE ip_address = ? AND endpoint = 'register'
        ");
        $stmt->execute([$ip]);
        $limit = $stmt->fetch();

        if ($limit && $limit['blocked_until'] && strtotime($limit['blocked_until']) > time()) {
            $this->response['errors'][] = 'Too many attempts. Please try again later.';
            return false;
        }

        if ($limit) {
            $timePassed = time() - strtotime($limit['last_attempt']);
            if ($timePassed < RATE_LIMIT_TIMEFRAME && $limit['attempts'] >= RATE_LIMIT_MAX_ATTEMPTS) {
                // Block the IP
                $stmt = $this->pdo->prepare("
                    UPDATE rate_limits 
                    SET blocked_until = DATE_ADD(NOW(), INTERVAL ? SECOND)
                    WHERE ip_address = ? AND endpoint = 'register'
                ");
                $stmt->execute([RATE_LIMIT_BLOCKTIME, $ip]);
                
                $this->response['errors'][] = 'Too many attempts. Please try again later.';
                return false;
            }

            // Update attempts
            $stmt = $this->pdo->prepare("
                UPDATE rate_limits 
                SET attempts = IF(? > RATE_LIMIT_TIMEFRAME, 1, attempts + 1),
                    last_attempt = NOW()
                WHERE ip_address = ? AND endpoint = 'register'
            ");
            $stmt->execute([$timePassed, $ip]);
        } else {
            // First attempt
            $stmt = $this->pdo->prepare("
                INSERT INTO rate_limits (ip_address, endpoint, attempts, last_attempt)
                VALUES (?, 'register', 1, NOW())
            ");
            $stmt->execute([$ip]);
        }

        return true;
    }

    private function sanitizeInput(): array {
        return [
            'username' => filter_input(INPUT_POST, 'username', FILTER_SANITIZE_STRING),
            'email' => filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL),
            'password' => $_POST['password'] ?? '',
            'confirm_password' => $_POST['confirm_password'] ?? ''
        ];
    }

    private function validateInput(array $data): bool {
        // Username validation
        if (!preg_match('/^[a-zA-Z0-9_-]{3,20}$/', $data['username'])) {
            $this->response['errors'][] = 'Invalid username format';
            return false;
        }

        // Email validation
        if (!filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
            $this->response['errors'][] = 'Invalid email format';
            return false;
        }

        // Password validation
        if (strlen($data['password']) < 12) {
            $this->response['errors'][] = 'Password must be at least 12 characters long';
            return false;
        }

        if (!preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z\d]).+$/', $data['password'])) {
            $this->response['errors'][] = 'Password must include uppercase, lowercase, numbers, and special characters';
            return false;
        }

        if ($data['password'] !== $data['confirm_password']) {
            $this->response['errors'][] = 'Passwords do not match';
            return false;
        }

        return true;
    }

    private function isUniqueUser(array $data): bool {
        $stmt = $this->pdo->prepare("
            SELECT username, email 
            FROM users 
            WHERE username = ? OR email = ?
        ");
        $stmt->execute([$data['username'], $data['email']]);
        $existing = $stmt->fetch();

        if ($existing) {
            if ($existing['username'] === $data['username']) {
                $this->response['errors'][] = 'Username already taken';
            }
            if ($existing['email'] === $data['email']) {
                $this->response['errors'][] = 'Email already registered';
            }
            return false;
        }

        return true;
    }

    private function createUser(array $data): void {
        $verificationToken = bin2hex(random_bytes(32));
        $hashedPassword = password_hash($data['password'], HASH_ALGO, HASH_OPTIONS);

        $stmt = $this->pdo->prepare("
            INSERT INTO users (
                username, email, password, verification_token, created_at
            ) VALUES (?, ?, ?, ?, NOW())
        ");

        if ($stmt->execute([
            $data['username'],
            $data['email'],
            $hashedPassword,
            $verificationToken
        ])) {
            $userId = $this->pdo->lastInsertId();
            $this->logAudit($userId, 'user_registered');
            $this->sendVerificationEmail($data['email'], $verificationToken);
            
            $this->response['success'] = true;
            $this->response['message'] = 'Registration successful! Please check your email to verify your account.';
        } else {
            throw new Exception('Failed to create user');
        }
    }

    private function sendVerificationEmail(string $email, string $token): void {
        // Email sending logic here
        // This is a placeholder - implement your email sending logic
    }

    private function logAudit($userId, $eventType): void {
        $stmt = $this->pdo->prepare("
            INSERT INTO audit_logs (
                user_id, event_type, ip_address, user_agent, details
            ) VALUES (?, ?, ?, ?, ?)
        ");

        $details = json_encode([
            'timestamp' => time(),
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown',
            'referrer' => $_SERVER['HTTP_REFERER'] ?? 'Direct'
        ]);

        $stmt->execute([
            $userId,
            $eventType,
            $this->getClientIP(),
            $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown',
            $details
        ]);
    }

    private function logError(string $message, Exception $e): void {
        error_log(sprintf(
            "[%s] %s: %s in %s:%d\nStack trace:\n%s",
            date('Y-m-d H:i:s'),
            $message,
            $e->getMessage(),
            $e->getFile(),
            $e->getLine(),
            $e->getTraceAsString()
        ));
    }

    private function getClientIP(): string {
        $headers = ['HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_X_CLUSTER_CLIENT_IP', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED', 'REMOTE_ADDR'];
        
        foreach ($headers as $header) {
            if (!empty($_SERVER[$header])) {
                $ips = explode(',', $_SERVER[$header]);
                $ip = trim($ips[0]);
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }
        
        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }

    private function logSecurityEvent(string $message): void {
        $logEntry = sprintf(
            "[%s] Security Event: %s - IP: %s, User-Agent: %s\n",
            date('Y-m-d H:i:s'),
            $message,
            $this->getClientIP(),
            $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown'
        );
        
        error_log($logEntry, 3, AUDIT_LOG_FILE);
    }

    private function sendResponse(): void {
        header('Content-Type: application/json');
        echo json_encode($this->response);
        exit;
    }
}

// Initialize and handle registration
$handler = new RegistrationHandler();
$handler->handleRegistration();
