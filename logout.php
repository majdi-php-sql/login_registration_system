<?php
session_start();
require 'functions.php';

if (isset($_SESSION['email'])) {
    $email = $_SESSION['email'];
    $conn = get_db_connection();
    if ($conn) {
        $stmt = $conn->prepare("DELETE FROM sessions WHERE user_id = (SELECT id FROM users WHERE email = :email)");
        $stmt->bindParam(':email', $email);
        $stmt->execute();
    }
    session_unset();
    session_destroy();
}

header('Location: index.php');
exit();
