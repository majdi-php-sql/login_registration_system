<?php
session_start();
require_once 'functions.php'; // Assuming functions.php contains get_db_connection()

// Ensure CSRF token is valid
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die('Invalid CSRF token.');
    }

    $otp_code = trim($_POST['otp_code']);
    if (empty($otp_code)) {
        die('OTP code cannot be empty.');
    }

    // Connect to the database
    $conn = get_db_connection();

    // Prepare and execute query to verify OTP
    $stmt = $conn->prepare("SELECT id, otp_expiry FROM users WHERE otp_code = ?");
    $stmt->bind_param("s", $otp_code);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows > 0) {
        $stmt->bind_result($user_id, $otp_expiry);
        $stmt->fetch();

        // Check if OTP has expired
        if (new DateTime() > new DateTime($otp_expiry)) {
            echo 'OTP has expired. Please request a new one.';
        } else {
            // OTP is valid
            // Here you should handle the successful OTP verification (e.g., update user status)
            echo 'OTP verified successfully!';
        }
    } else {
        echo 'Invalid OTP code.';
    }

    $stmt->close();
    $conn->close();
}

// Generate a new CSRF token for the form
$_SESSION['csrf_token'] = bin2hex(random_bytes(32));
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OTP Verification</title>
</head>
<body>
    <form action="otp_verification.php" method="POST">
        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
        <label for="otp_code">Enter OTP:</label>
        <input type="text" id="otp_code" name="otp_code" required>
        <button type="submit">Verify OTP</button>
    </form>
</body>
</html>
