<?php
// otp_verification.php
session_start();
require 'config.php';
require 'functions.php';

if (!isset($_SESSION['username'])) {
    header('Location: index.php');
    exit();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $otp = filter_input(INPUT_POST, 'otp', FILTER_SANITIZE_STRING);

    if (verify_otp($_SESSION['username'], $otp)) {
        $_SESSION['logged_in'] = true;
        header('Location: dashboard.php');
        exit();
    } else {
        echo 'Invalid OTP';
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OTP Verification</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
    <form method="post" action="">
        <label for="otp">OTP:</label>
        <input type="text" id="otp" name="otp" required>
        <button type="submit">Verify OTP</button>
    </form>
</body>
</html>
