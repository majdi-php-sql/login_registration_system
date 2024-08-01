<?php
session_start(); // I kicked off the session for handling user data.
require '../includes/functions.php'; // I pulled in the functions from the includes folder.
# Redirect to dashboard if already logged in
if (isset($_SESSION['user_id'])) { // I checked if the user is already logged in.
    header('Location: dashboard.php'); // I sent them to the dashboard if they are.
    exit(); // I made sure no more code runs after the redirect.
}

# Handle login
if (isset($_POST['login'])) { // I checked if the form was submitted.
    $username = $_POST['username']; // I grabbed the username from the form.
    $password = $_POST['password']; // I got the password from the form.
    $csrf_token = $_POST['csrf_token']; // I fetched the CSRF token from the form.

    if (!hash_equals($_SESSION['csrf_token'], $csrf_token)) { // I verified the CSRF token.
        log_security_event('CSRF token validation failed.'); // I logged a security event if CSRF token validation failed.
        die('Invalid CSRF token'); // I killed the script with an error message if the CSRF token is invalid.
    }

    if (!limit_login_attempts($username)) { // I checked if the login attempts limit was reached.
        die('Account is locked. Please try again later.'); // I stopped the script if the account is locked.
    }

    $user = validate_user($username, $password); // I validated the user's credentials.

    if ($user) { // If user validation passed.
        session_regenerate_id(true); // I regenerated the session ID for security.
        $_SESSION['user_id'] = $user['id']; // I stored the user ID in the session.
        header('Location: otp_verification.php'); // I redirected to the OTP verification page.
        exit(); // I made sure no more code runs after the redirect.
    } else {
        increment_login_attempts($username); // I incremented the login attempts if login failed.
        log_security_event("Failed login attempt for username: $username"); // I logged a security event for the failed login.
        echo 'Invalid username or password.'; // I showed an error message if the login failed.
    }
}

# Generate CSRF token
$_SESSION['csrf_token'] = bin2hex(random_bytes(32)); // I generated a new CSRF token.
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8"> <!-- I set the character encoding for the page. -->
    <title>Login</title> <!-- I set the title of the page. -->
    <link rel="stylesheet" href="../styles/styles.css"> <!-- I linked to the stylesheet for styling. -->
</head>

<body>
    <form method="POST" action="index.php"> <!-- I set up the form to post data to the login page. -->
        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>"> <!-- I included the CSRF token in the form. -->
        <label for="username">Username:</label> <!-- I labeled the username field. -->
        <input type="text" id="username" name="username" required> <!-- I created a text input for the username. -->
        <label for="password">Password:</label> <!-- I labeled the password field. -->
        <input type="password" id="password" name="password" required> <!-- I created a password input for secure entry. -->
        <button type="submit" name="login">Login</button> <!-- I created a submit button for the form. -->
        <div id="form-footer">
            <p>Don't have an account? <a href="registration.php">Register</a></p>
        </div>
    </form>
</body>

</html>