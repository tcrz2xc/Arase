<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Registration</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/zxcvbn/4.4.2/zxcvbn.js"></script>
    <style>
        :root {
            --primary-color: #4a90e2;
            --error-color: #e74c3c;
            --success-color: #2ecc71;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background: #f5f5f5;
        }

        .container {
            max-width: 500px;
            margin: 40px auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }

        .form-group {
            margin-bottom: 20px;
        }

        label {
            display: block;
            margin-bottom: 5px;
            font-weight: 500;
        }

        input {
            width: 100%;
            padding: 8px;
            border: 2px solid #ddd;
            border-radius: 4px;
            font-size: 16px;
            transition: border-color 0.3s ease;
        }

        input:focus {
            border-color: var(--primary-color);
            outline: none;
        }

        button {
            background: var(--primary-color);
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 4px;
            font-size: 16px;
            cursor: pointer;
            width: 100%;
            transition: background-color 0.3s ease;
        }

        button:hover {
            background: #357abd;
        }

        button:disabled {
            background: #ccc;
            cursor: not-allowed;
        }

        .error {
            color: var(--error-color);
            font-size: 14px;
            margin-top: 5px;
        }

        .success {
            color: var(--success-color);
            font-size: 14px;
            margin-top: 5px;
        }

        .password-strength {
            margin-top: 5px;
            height: 5px;
            background: #ddd;
            border-radius: 3px;
            overflow: hidden;
        }

        .password-strength-bar {
            height: 100%;
            width: 0;
            transition: width 0.3s ease, background-color 0.3s ease;
        }

        .strength-text {
            font-size: 12px;
            margin-top: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h2>Create Account</h2>
        <form id="registrationForm" novalidate>
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required
                       pattern="^[a-zA-Z0-9_-]{3,20}$"
                       title="Username must be between 3-20 characters and can only contain letters, numbers, underscores, and hyphens">
                <div class="error" id="username-error"></div>
            </div>

            <div class="form-group">
                <label for="email">Email</label>
                <input type="email" id="email" name="email" required>
                <div class="error" id="email-error"></div>
            </div>

            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required
                       minlength="12"
                       title="Password must be at least 12 characters long and include uppercase, lowercase, numbers, and special characters">
                <div class="password-strength">
                    <div class="password-strength-bar"></div>
                </div>
                <div class="strength-text"></div>
                <div class="error" id="password-error"></div>
            </div>

            <div class="form-group">
                <label for="confirm_password">Confirm Password</label>
                <input type="password" id="confirm_password" name="confirm_password" required>
                <div class="error" id="confirm-password-error"></div>
            </div>

            <input type="hidden" name="csrf_token" id="csrf_token">
            <button type="submit" id="submit-btn" disabled>Create Account</button>
        </form>
        <div id="form-message"></div>
    </div>

    <script>
        document.addEventListener('DOMContentLoaded', function() {
            // Fetch CSRF token
            fetch('/get-csrf-token.php')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('csrf_token').value = data.token;
                });

            const form = document.getElementById('registrationForm');
            const passwordInput = document.getElementById('password');
            const strengthBar = document.querySelector('.password-strength-bar');
            const strengthText = document.querySelector('.strength-text');
            const submitBtn = document.getElementById('submit-btn');

            // Password strength checker
            passwordInput.addEventListener('input', function() {
                const result = zxcvbn(this.value);
                const strength = (result.score * 25);
                strengthBar.style.width = strength + '%';
                
                const colors = ['#e74c3c', '#e67e22', '#f1c40f', '#2ecc71', '#27ae60'];
                strengthBar.style.backgroundColor = colors[result.score];
                
                const texts = ['Very Weak', 'Weak', 'Fair', 'Strong', 'Very Strong'];
                strengthText.textContent = 'Password Strength: ' + texts[result.score];
                
                // Enable submit button only if password is strong enough
                submitBtn.disabled = result.score < 3;
            });

            // Form validation
            form.addEventListener('submit', function(e) {
                e.preventDefault();
                
                if (validateForm()) {
                    const formData = new FormData(form);
                    
                    fetch('/register.php', {
                        method: 'POST',
                        body: formData,
                        headers: {
                            'X-Requested-With': 'XMLHttpRequest'
                        }