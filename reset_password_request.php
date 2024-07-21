<?php
session_start();
require 'functions.php';

generate_csrf_token();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = $_POST['email'] ?? '';
    $csrf_token = $_POST['csrf_token'] ?? '';

    if (validate_csrf_token($csrf_token) && filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $reset_token = generate_reset_token($email);
        if ($reset_token) {
            $message = 'Password reset email sent.';
        } else {
            $error = 'Failed to generate reset token.';
        }
    } else {
        $error = 'Invalid email or CSRF token.';
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Reset Password Request</title>
</head>
<body>
    <?php if (isset($message)): ?>
        <p><?php echo htmlspecialchars($message); ?></p>
    <?php elseif (isset($error)): ?>
        <p><?php echo htmlspecialchars($error); ?></p>
    <?php endif; ?>
    <form action="reset_password_request.php" method="post">
        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
        <label for="email">Email:</label>
        <input type="email" name="email" id="email" required>
        <button type="submit">Request Password Reset</button>
    </form>
</body>
</html>
