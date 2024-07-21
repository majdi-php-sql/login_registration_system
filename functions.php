<?php
// functions.php
require 'config.php';
require 'vendor/autoload.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

function connect_db() {
    global $conn;
    return $conn;
}

function validate_user($username, $password) {
    $conn = connect_db();
    $stmt = $conn->prepare("SELECT id, username, password, login_attempts, lockout_time FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($result->num_rows === 1) {
        $user = $result->fetch_assoc();
        // Check for account lockout
        if ($user['login_attempts'] >= 5 && strtotime($user['lockout_time']) > time()) {
            die('Account is locked. Try again later.');
        }
        // Verify password
        if (password_verify($password, $user['password'])) {
            // Reset login attempts on successful login
            $stmt = $conn->prepare("UPDATE users SET login_attempts = 0, lockout_time = NULL WHERE id = ?");
            $stmt->bind_param("i", $user['id']);
            $stmt->execute();
            // Check if rehashing is necessary
            if (password_needs_rehash($user['password'], PASSWORD_DEFAULT)) {
                $newHash = password_hash($password, PASSWORD_DEFAULT);
                $stmt = $conn->prepare("UPDATE users SET password = ? WHERE id = ?");
                $stmt->bind_param("si", $newHash, $user['id']);
                $stmt->execute();
            }
            return true;
        } else {
            // Increment login attempts on failed login
            $stmt = $conn->prepare("UPDATE users SET login_attempts = login_attempts + 1, lockout_time = IF(login_attempts >= 4, DATE_ADD(NOW(), INTERVAL 30 MINUTE), NULL) WHERE id = ?");
            $stmt->bind_param("i", $user['id']);
            $stmt->execute();
            return false;
        }
    }
    return false;
}

function generate_otp($username) {
    $otp = random_int(100000, 999999);
    $expiry = date('Y-m-d H:i:s', strtotime('+5 minutes'));
    $conn = connect_db();
    $stmt = $conn->prepare("UPDATE users SET otp_code = ?, otp_expiry = ? WHERE username = ?");
    $stmt->bind_param("sss", $otp, $expiry, $username);
    $stmt->execute();
    return $otp;
}

function verify_otp($username, $otp) {
    $conn = connect_db();
    $stmt = $conn->prepare("SELECT otp_code, otp_expiry FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($result->num_rows === 1) {
        $user = $result->fetch_assoc();
        if ($user['otp_code'] === $otp && strtotime($user['otp_expiry']) > time()) {
            // Clear OTP after successful verification
            $stmt = $conn->prepare("UPDATE users SET otp_code = NULL, otp_expiry = NULL WHERE username = ?");
            $stmt->bind_param("s", $username);
            $stmt->execute();
            return true;
        }
    }
    return false;
}

function send_otp_email($username, $otp) {
    $conn = connect_db();
    $stmt = $conn->prepare("SELECT email FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($result->num_rows === 1) {
        $user = $result->fetch_assoc();
        $mail = new PHPMailer(true);
        try {
            // Server settings
            $mail->isSMTP();
            $mail->Host = 'smtp.example.com';
            $mail->SMTPAuth = true;
            $mail->Username = 'your-email@example.com';
            $mail->Password = 'your-email-password';
            $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
            $mail->Port = 587;
            // Recipients
            $mail->setFrom('your-email@example.com', 'Your Name');
            $mail->addAddress($user['email']);
            // Content
            $mail->isHTML(true);
            $mail->Subject = 'Your OTP Code';
            $mail->Body    = "Your OTP code is $otp.";
            $mail->send();
        } catch (Exception $e) {
            // Handle email sending failure
        }
    }
}
?>
