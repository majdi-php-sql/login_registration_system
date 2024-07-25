<?php
session_start(); // I kicked off the session for handling user data.
require '../includes/functions.php'; // I pulled in the functions from the includes folder.

# Check if the user is logged in
if (!isset($_SESSION['user_id'])) { // I checked if the user isn't logged in.
    header('Location: index.php'); // I sent them to the login page if they aren't.
    exit(); // I made sure no more code runs after the redirect.
}

# Handle OTP verification
if ($_SERVER['REQUEST_METHOD'] === 'POST') { // I checked if the form was submitted.
    $otp_code = $_POST['otp_code']; // I grabbed the OTP code from the form.
    $user_id = $_SESSION['user_id']; // I got the user ID from the session.

    if (validate_otp($user_id, $otp_code)) { // I validated the OTP code.
        session_regenerate_id(true); // I regenerated the session ID for security.
        $_SESSION['authenticated'] = true; // I marked the user as authenticated.
        header('Location: dashboard.php'); // I redirected to the dashboard.
        exit(); // I made sure no more code runs after the redirect.
    } else {
        log_security_event("Failed OTP verification for user ID: $user_id"); // I logged a security event for the failed OTP verification.
        echo 'Invalid OTP code.'; // I showed an error message if the OTP validation failed.
    }
}

# Generate and send OTP
generate_and_send_otp($_SESSION['user_id']); // I generated and sent an OTP to the user.
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"> <!-- I set the character encoding for the page. -->
    <title>OTP Verification</title> <!-- I set the title of the page. -->
    <link rel="stylesheet" href="../styles/styles.css"> <!-- I linked to the stylesheet for styling. -->
</head>
<body>
    <form method="POST" action="otp_verification.php"> <!-- I set up the form to post data to the OTP verification page. -->
        <label for="otp_code">Enter OTP:</label> <!-- I labeled the OTP code field. -->
        <input type="text" id="otp_code" name="otp_code" required> <!-- I created a text input for the OTP code. -->
        <button type="submit">Verify</button> <!-- I created a submit button for the form. -->
    </form>
</body>
</html>