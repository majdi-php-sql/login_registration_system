<?php
session_start(); // I kicked off the session for user handling.
require '../includes/functions.php'; // I pulled in the functions from the includes folder.

# Handle registration
if ($_SERVER['REQUEST_METHOD'] === 'POST') { // I checked if the form was submitted.
    $username = $_POST['username']; // I grabbed the username from the form.
    $email = $_POST['email']; // I got the email from the form.
    $password = $_POST['password']; // I pulled the password from the form.
    $role = $_POST['role']; // I got the user role from the form.

    if (validate_registration($username, $email, $password, $role)) { // I validated the registration data.
        if (register_user($username, $email, $password, $role)) { // I tried to register the user.
            header('Location: index.php'); // I redirected to the homepage if registration was successful.
            exit(); // I made sure no more code runs after the redirect.
        } else {
            echo 'Registration failed. Please try again.'; // I threw an error if registration failed.
        }
    } else {
        echo 'Invalid registration data.'; // I showed an error if validation failed.
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"> <!-- I set the character encoding for the page. -->
    <title>Register</title> <!-- I set the title of the page. -->
    <link rel="stylesheet" href="../styles/styles.css"> <!-- I linked to the stylesheet for styling. -->
</head>
<body>
    <form method="POST" action="registration.php"> <!-- I set up the form to post data to the registration page. -->
        <label for="username">Username:</label> <!-- I labeled the username field. -->
        <input type="text" id="username" name="username" required> <!-- I created a text input for the username. -->
        <label for="email">Email:</label> <!-- I labeled the email field. -->
        <input type="email" id="email" name="email" required> <!-- I created an email input for the user. -->
        <label for="password">Password:</label> <!-- I labeled the password field. -->
        <input type="password" id="password" name="password" required> <!-- I created a password input for secure entry. -->
        <label for="role">Role:</label> <!-- I labeled the role selection field. -->
        <select id="role" name="role" required> <!-- I created a dropdown for role selection. -->
            <option value="administrator">Administrator</option> <!-- I added an option for Administrator. -->
            <option value="admin">Admin</option> <!-- I added an option for Admin. -->
            <option value="lawyer">Lawyer</option> <!-- I added an option for Lawyer. -->
            <option value="staff">Staff</option> <!-- I added an option for Staff. -->
            <option value="finance">Finance</option> <!-- I added an option for Finance. -->
            <option value="reception">Reception</option> <!-- I added an option for Reception. -->
        </select>
        <button type="submit">Register</button> <!-- I created a submit button for the form. -->
    </form>
</body>
</html>