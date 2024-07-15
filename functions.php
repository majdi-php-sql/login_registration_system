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
    $stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($result->num_rows === 1) {
        $user = $result->fetch_assoc();
        if (password_verify($password, $user['password'])) {
            return $user;
        }
    }
    return false;
}

function generate_otp($username) {
    $otp = rand(100000, 999999);
    $otp_expiry = date('Y-m-d H:i:s', strtotime('+10 minutes'));
    $conn = connect_db();
    $stmt = $conn->prepare("UPDATE users SET otp_code = ?, otp_expiry = ? WHERE username = ?");
    $stmt->bind_param("sss", $otp, $otp_expiry, $username);
    $stmt->execute();
    return $otp;
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
            $mail->isSMTP();
            $mail->Host = 'smtp.example.com';
            $mail->SMTPAuth = true;
            $mail->Username = 'your-email@example.com';
            $mail->Password = 'your-email-password';
            $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
            $mail->Port = 587;
            $mail->setFrom('no-reply@example.com', 'OTP Verification');
            $mail->addAddress($user['email']);
            $mail->isHTML(true);
            $mail->Subject = 'Your OTP Code';
            $mail->Body = 'Your OTP code is ' . $otp;
            $mail->send();
        } catch (Exception $e) {
            error_log('OTP email could not be sent. Mailer Error: ' . $mail->ErrorInfo);
        }
    }
}

function verify_otp($username, $otp) {
    $conn = connect_db();
    $stmt = $conn->prepare("SELECT otp_code, otp_expiry FROM users WHERE username = ? AND otp_code = ? AND otp_expiry > NOW()");
    $stmt->bind_param("ss", $username, $otp);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($result->num_rows === 1) {
        $stmt = $conn->prepare("UPDATE users SET otp_code = NULL, otp_expiry = NULL WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        return true;
    }
    return false;
}

function register_user($username, $email, $password, $role) {
    $conn = connect_db();
    $hashed_password = password_hash($password, PASSWORD_BCRYPT);
    $stmt = $conn->prepare("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)");
    $stmt->bind_param("ssss", $username, $email, $hashed_password, $role);
    return $stmt->execute();
}
?>
