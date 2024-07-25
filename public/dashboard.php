<?php
session_start(); // I kicked off the session to keep track of user data.
require '../includes/functions.php'; // I pulled in the functions from the includes folder.

# Check if the user is logged in and authenticated
if (!isset($_SESSION['user_id']) || !isset($_SESSION['authenticated'])) { // I checked if the user isn't logged in or authenticated.
    header('Location: index.php'); // I sent them to the login page if they aren't.
    exit(); // I made sure no more code runs after the redirect.
}

# Handle logout
if (isset($_GET['logout'])) { // I checked if the user clicked the logout link.
    session_unset(); // I cleared all session variables.
    session_destroy(); // I destroyed the session to log out the user.
    header('Location: index.php'); // I redirected to the login page after logging out.
    exit(); // I made sure no more code runs after the redirect.
}

$user = get_user($_SESSION['user_id']); // I fetched the user data using their session ID.
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"> <!-- I set the character encoding for the page. -->
    <title>Dashboard</title> <!-- I set the title of the page. -->
    <link rel="stylesheet" href="../styles/styles.css"> <!-- I linked to the stylesheet for styling. -->
</head>
<body>
    <h1>Welcome, <?php echo htmlspecialchars($user['username']); ?>!</h1> <!-- I greeted the user and showed their username securely. -->
    <a href="index.php?logout=true">Logout</a> <!-- I created a logout link to allow the user to log out. -->
</body>
</html>