<?php
require '../vendor/autoload.php'; // I loaded all the cool dependencies, including PHPMailer

use Aws\Kms\KmsClient; // I pulled in the KMS Client for AWS
use PHPMailer\PHPMailer\PHPMailer; // I grabbed PHPMailer to handle sending emails

// Load environment variables from the .env file
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/../config'); // I set up Dotenv to load environment variables
$dotenv->load(); // I loaded those environment variables into the app

function connect_db() { // I whipped up a function to connect to the database
    $host = getenv('localhost'); // I fetched the DB host from the environment variables
    $db = getenv('secureloginsystem'); // I grabbed the DB name from the environment variables
    $user = getenv('root'); // I got the DB user from the environment variables
    $pass = getenv(''); // I picked up the DB password from the environment variables

    $dsn = "mysql:host=$host;dbname=$db;charset=utf8mb4"; // I put together the DSN string for PDO
    try {
        return new PDO($dsn, $user, $pass, [ // I tried to make a new PDO connection
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, // I set it to throw exceptions on errors
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC, // I told PDO to fetch results as associative arrays
        ]);
    } catch (PDOException $e) { // I caught any issues that popped up
        die('Database connection failed: ' . $e->getMessage()); // I killed the script with an error message if connection failed
    }
}

function log_security_event($message) { // I set up a function to log security events
    $logfile = '/path/to/secure/logs/security.log'; // I specified where to put the log
    $date = date('Y-m-d H:i:s'); // I grabbed the current date and time
    file_put_contents($logfile, "[$date] $message" . PHP_EOL, FILE_APPEND); // I wrote the log message to the file
}

function validate_registration($username, $email, $password, $role) { // I created a function to validate user registration data
    // Add your validation logic here
    return true; // I’m pretending validation always passes for now
}

function register_user($username, $email, $password, $role) { // I set up the function to register a new user
    $pdo = connect_db(); // I got a PDO instance to talk to the database
    $hashed_password = password_hash($password, PASSWORD_BCRYPT); // I hashed the user’s password

    $stmt = $pdo->prepare('INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)'); // I prepped the SQL statement to insert a new user
    return $stmt->execute([$username, $email, $hashed_password, $role]); // I ran the statement with user data
}

function validate_user($username, $password) { // I set up the function to validate a user’s login
    $pdo = connect_db(); // I got a PDO instance to access the database
    $stmt = $pdo->prepare('SELECT * FROM users WHERE username = ?'); // I prepped the SQL statement to get user data
    $stmt->execute([$username]); // I executed the statement with the username
    $user = $stmt->fetch(); // I fetched the user data

    if ($user && password_verify($password, $user['password'])) { // I checked if the user exists and the password is correct
        return $user; // I returned the user data if everything checks out
    }

    return false; // I returned false if the user doesn’t exist or password is wrong
}

function generate_and_send_otp($user_id) { // I made a function to generate and send an OTP
    $otp = rand(100000, 999999); // I cranked out a random 6-digit OTP
    $otp_hash = hash('sha256', $otp); // I hashed the OTP
    $expiry = date('Y-m-d H:i:s', strtotime('+10 minutes')); // I set the OTP to expire in 10 minutes

    $pdo = connect_db(); // I got a PDO instance to access the database
    $stmt = $pdo->prepare('UPDATE users SET otp_hash = ?, otp_expiry = ? WHERE id = ?'); // I prepped the SQL statement to update the OTP data
    $stmt->execute([$otp_hash, $expiry, $user_id]); // I ran the statement with the OTP details

    send_otp_email($otp); // I sent the OTP via email
}

function validate_otp($user_id, $otp) { // I set up a function to validate the OTP
    $otp_hash = hash('sha256', $otp); // I hashed the provided OTP
    $pdo = connect_db(); // I got a PDO instance to access the database
    $stmt = $pdo->prepare('SELECT otp_hash, otp_expiry FROM users WHERE id = ?'); // I prepped the SQL statement to get OTP data
    $stmt->execute([$user_id]); // I executed the statement with the user ID
    $user = $stmt->fetch(); // I fetched the user data

    if ($user && $user['otp_hash'] === $otp_hash && strtotime($user['otp_expiry']) > time()) { // I checked if the OTP is valid and hasn’t expired
        return true; // I returned true if the OTP is good
    }

    return false; // I returned false if the OTP is invalid or expired
}

function send_otp_email($otp) { // I set up the function to send the OTP via email
    $mail = new PHPMailer(); // I created a new PHPMailer instance
    $mail->isSMTP(); // I set it up to use SMTP
    $mail->Host = 'smtp.example.com'; // I specified the SMTP server
    $mail->SMTPAuth = true; // I turned on SMTP authentication
    $mail->Username = getenv('SMTP_USER'); // I pulled the SMTP username from the environment
    $mail->Password = getenv('SMTP_PASS'); // I pulled the SMTP password from the environment
    $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS; // I set it to use STARTTLS encryption
    $mail->Port = 587; // I specified the SMTP port

    $mail->setFrom('no-reply@example.com', 'Your App'); // I set the sender’s email and name
    $mail->addAddress('user@example.com'); // I added the recipient email (should be pulled from the database)
    $mail->Subject = 'Your OTP Code'; // I set the subject of the email
    $mail->Body = "Your OTP code is: $otp"; // I set the body of the email with the OTP

    $mail->send(); // I sent the email
}

function get_user($user_id) { // I made a function to get user data by ID
    $pdo = connect_db(); // I got a PDO instance to access the database
    $stmt = $pdo->prepare('SELECT username FROM users WHERE id = ?'); // I prepped the SQL statement to get the username
    $stmt->execute([$user_id]); // I ran the statement with the user ID
    return $stmt->fetch(); // I returned the fetched user data
}

function limit_login_attempts($username) { // I set up a function to limit login attempts
    // Implement login attempt limiting
    return true; // I’m assuming it always returns true for now
}

function increment_login_attempts($username) { // I made a function to increment the login attempts count
    // Implement logic to increment login attempts count
}

function csrf_token() { // I set up a function to get the CSRF token
    return $_SESSION['csrf_token']; // I returned the CSRF token from the session
}
