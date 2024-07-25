CREATE DATABASE SecureLoginSystem; -- I set up the database for the login system.
USE SecureLoginSystem; -- I switched to using the SecureLoginSystem database.

-- Users table
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY, -- I made an auto-incrementing ID for each user.
    username VARCHAR(50) NOT NULL UNIQUE, -- I set a unique username field for each user.
    email VARCHAR(255) NOT NULL UNIQUE, -- I made sure each user has a unique email.
    password VARBINARY(255) NOT NULL, -- I encrypted the user passwords.
    role ENUM('administrator', 'admin', 'lawyer', 'staff', 'finance', 'reception') NOT NULL, -- I added roles for user permissions.
    otp_hash CHAR(64), -- I created a field to store OTP hash for two-factor authentication.
    otp_expiry DATETIME, -- I added a field to track OTP expiry.
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, -- I set up a timestamp for when users are created.
    login_attempts INT DEFAULT 0, -- I kept track of how many times a user tried to log in.
    lockout_time DATETIME, -- I added a field for lockout time after failed login attempts.
    account_status ENUM('active', 'suspended') DEFAULT 'active' -- I set the account status to either active or suspended.
);

-- Logs table
CREATE TABLE logs (
    id INT AUTO_INCREMENT PRIMARY KEY, -- I made an auto-incrementing ID for each log entry.
    user_id INT NOT NULL, -- I added a field for user ID to link logs to users.
    action VARCHAR(255) NOT NULL, -- I recorded the action taken by the user.
    ip_address VARCHAR(45), -- I tracked the IP address where the action came from.
    user_agent TEXT, -- I logged the user agent (browser details) for the action.
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, -- I timestamped each log entry.
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE -- I made sure logs are deleted if the associated user is deleted.
);

-- Sessions table
CREATE TABLE sessions (
    id INT AUTO_INCREMENT PRIMARY KEY, -- I set up an auto-incrementing ID for each session.
    user_id INT NOT NULL, -- I linked each session to a user.
    session_id CHAR(64) NOT NULL UNIQUE, -- I created a unique session ID for each user session.
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, -- I timestamped when the session was created.
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, -- I updated the last activity timestamp whenever there's activity.
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE -- I ensured sessions are deleted if the associated user is deleted.
);