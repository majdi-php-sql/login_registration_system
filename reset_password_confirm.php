<?php
session_start();
require 'functions.php';

if (isset($_GET['token'])) {
    $reset_token = $_GET['token'];

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $new_password = $_POST['new_password'] ?? '';
        $csrf_token = $_POST['csrf_token'] ?? '';

        if (validate_csrf_token($csrf_token) && !empty($new_password)) {
            if (reset_user_password($reset_token, $new_password)) {
                $message = 'Password has been reset.';
            } else {
                $error = 'Failed to reset password.';
            }
        } else {
            $error = 'Invalid CSRF token or password.';
        }
    }
} else {
    header('Location: index.php');
    exit();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Reset Password</title>
</head>
<body>
    <?php if (isset($message)): ?>
        <p><?php echo htmlspecialchars($message); ?></p>
    <?php elseif (isset($error)): ?>
        <p><?php echo htmlspecialchars($error); ?></p>
    <?php endif; ?>
    <form action="reset_password_confirm.php?token=<?php echo htmlspecialchars($reset_token); ?>" method="post">
        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
        <label for="new_password">New Password:</label>
        <input type="password" name="new_password" id="new_password" required>
        <button type="submit">Reset Password</button>
    </form>
</body>
</html>
