<?php
// get-csrf-token.php
require_once 'config.php';

class CSRFTokenGenerator {
    private $response = [
        'success' => false,
        'token' => null
    ];

    public function __construct() {
        $this->initializeSession();
    }

    private function initializeSession(): void {
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

    public function generateToken(): void {
        try {
            $token = bin2hex(random_bytes(32));
            $_SESSION['csrf_token'] = $token;
            $_SESSION['csrf_token_time'] = time();
            
            $this->response['success'] = true;
            $this->response['token'] = $token;
            
        } catch (Exception $e) {
            error_log("CSRF token generation failed: " . $e->getMessage());
            http_response_code(500);
        }

        $this->sendResponse();
    }

    private function sendResponse(): void {
        header('Content-Type: application/json');
        echo json_encode($this->response);
        exit;
    }
}

$generator = new CSRFTokenGenerator();
$generator->generateToken();
