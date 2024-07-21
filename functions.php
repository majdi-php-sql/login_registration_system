<?php

function get_db_connection() {
    static $conn = null;
    if ($conn === null) {
        $host = 'localhost';
        $db = 'SecureLoginSystem';
        $user = 'root';
        $pass = '';
        try {
            $conn = new PDO("mysql:host=$host;dbname=$db", $user, $pass);
            $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        } catch (PDOException $e) {
            error_log($e->getMessage());
            return false;
        }
    }
    return $conn;
}

function generate_csrf_token() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
}

function validate_csrf_token($csrf_token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $csrf_token);
}

function validate_user_input($username, $email, $password, $csrf_token) {
    return !empty($username) && !empty($email) && !empty($password) && filter_var($email, FILTER_VALIDATE_EMAIL) && validate_csrf_token($csrf_token);
}

function register_user($username, $email, $password, $role) {
    $conn = get_db_connection();
    if (!$conn) {
        return false;
    }

    $hashed_password = password_hash($password, PASSWORD_BCRYPT);
    $stmt = $conn->prepare("INSERT INTO users (username, email, password, role) VALUES (:username, :email, :password, :role)");
    $stmt->bindParam(':username', $username);
    $stmt->bindParam(':email', $email);
    $stmt->bindParam(':password', $hashed_password);
    $stmt->bindParam(':role', $role);

    return $stmt->execute();
}

function validate_user_login($email, $password) {
    if (empty($email) || empty($password)) {
        return false;
    }

    $conn = get_db_connection();
    if (!$conn) {
        return false;
    }

    $stmt = $conn->prepare("SELECT id, password FROM users WHERE email = :email");
    $stmt->bindParam(':email', $email);
    $stmt->execute();
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user && password_verify($password, $user['password'])) {
        return $user['id'];
    } else {
        return false;
    }
}

function create_session($user_id) {
    $conn = get_db_connection();
    if (!$conn) {
        return false;
    }

    $session_id = bin2hex(random_bytes(32));
    $stmt = $conn->prepare("INSERT INTO sessions (user_id, session_id) VALUES (:user_id, :session_id)");
    $stmt->bindParam(':user_id', $user_id);
    $stmt->bindParam(':session_id', $session_id);

    return $stmt->execute();
}

function log_user_action($user_id, $action) {
    $conn = get_db_connection();
    if (!$conn) {
        return false;
    }

    $ip_address = $_SERVER['REMOTE_ADDR'];
    $user_agent = $_SERVER['HTTP_USER_AGENT'];
    $stmt = $conn->prepare("INSERT INTO logs (user_id, action, ip_address, user_agent) VALUES (:user_id, :action, :ip_address, :user_agent)");
    $stmt->bindParam(':user_id', $user_id);
    $stmt->bindParam(':action', $action);
    $stmt->bindParam(':ip_address', $ip_address);
    $stmt->bindParam(':user_agent', $user_agent);

    return $stmt->execute();
}

function send_email($to, $subject, $message) {
    // Use a proper email library or service for sending emails
    return mail($to, $subject, $message);
}

function validate_otp($email, $otp_code) {
    $conn = get_db_connection();
    if (!$conn) {
        return false;
    }

    $stmt = $conn->prepare("SELECT otp_code, otp_expiry FROM users WHERE email = :email");
    $stmt->bindParam(':email', $email);
    $stmt->execute();
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user && $user['otp_code'] === $otp_code && new DateTime() < new DateTime($user['otp_expiry'])) {
        return true;
    } else {
        return false;
    }
}

function reset_user_password($reset_token, $new_password) {
    $conn = get_db_connection();
    if (!$conn) {
        return false;
    }

    $hashed_password = password_hash($new_password, PASSWORD_BCRYPT);
    $stmt = $conn->prepare("UPDATE users SET password = :password WHERE reset_token = :reset_token");
    $stmt->bindParam(':password', $hashed_password);
    $stmt->bindParam(':reset_token', $reset_token);

    return $stmt->execute();
}

function generate_reset_token($email) {
    $conn = get_db_connection();
    if (!$conn) {
        return false;
    }

    $reset_token = bin2hex(random_bytes(32));
    $stmt = $conn->prepare("UPDATE users SET reset_token = :reset_token WHERE email = :email");
    $stmt->bindParam(':reset_token', $reset_token);
    $stmt->bindParam(':email', $email);

    if ($stmt->execute()) {
        return $reset_token;
    } else {
        return false;
    }
}
?>
