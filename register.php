<?php
session_start();
require 'functions.php';

generate_csrf_token();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $email = $_POST['email'] ?? '';
    $password = $_POST['password'] ?? '';
    $role = $_POST['role'] ?? '';
    $csrf_token = $_POST['csrf_token'] ?? '';

    if (validate_user_input($username, $email, $password, $csrf_token)) {
        if (register_user($username, $email, $password, $role)) {
            $message = 'Registration successful.';
        } else {
            $error = 'Registration failed.';
        }
    } else {
        $error = 'Invalid input or CSRF token.';
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Register</title>
</head>
<body>
    <?php if (isset($message)): ?>
        <p><?php echo htmlspecialchars($message); ?></p>
    <?php elseif (isset($error)): ?>
        <p><?php echo htmlspecialchars($error); ?></p>
    <?php endif; ?>
    <form action="register.php" method="post">
        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
        <label for="username">Username:</label>
        <input type="text" name="username" id="username" required>
        <label for="email">Email:</label>
        <input type="email" name="email" id="email" required>
        <label for="password">Password:</label>
        <input type="password" name="password" id="password" required>
        <label for="role">Role:</label>
        <select name="role" id="role" required>
            <option value="administrator">Administrator</option>
            <option value="admin">Admin</option>
            <option value="lawyer">Lawyer</option>
            <option value="staff">Staff</option>
            <option value="finance">Finance</option>
            <option value="reception">Reception</option>
        </select>
        <button type="submit">Register</button>
    </form>
</body>
</html>
