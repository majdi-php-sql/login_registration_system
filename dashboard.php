<?php
session_start();
require 'functions.php';

if (!isset($_SESSION['email'])) {
    header('Location: index.php');
    exit();
}

$email = $_SESSION['email'];
$conn = get_db_connection();
if ($conn) {
    $stmt = $conn->prepare("SELECT id, username, email, role FROM users WHERE email = :email");
    $stmt->bindParam(':email', $email);
    $stmt->execute();
    $user_data = $stmt->fetch(PDO::FETCH_ASSOC);
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Dashboard</title>
</head>
<body>
    <h1>Welcome, <?php echo htmlspecialchars($user_data['username']); ?>!</h1>
    <p>Email: <?php echo htmlspecialchars($user_data['email']); ?></p>
    <p>Role: <?php echo htmlspecialchars($user_data['role']); ?></p>
    <p><a href="logout.php">Logout</a></p>
</body>
</html>
