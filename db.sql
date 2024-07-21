CREATE DATABASE SecureLoginSystem;
USE SecureLoginSystem;

-- Users table
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(500) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    role ENUM('administrator', 'admin', 'lawyer', 'staff', 'finance', 'reception') NOT NULL,
    otp_code VARCHAR(6),
    otp_expiry DATETIME,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    login_attempts INT DEFAULT 0,
    lockout_time DATETIME
);

-- Logs table
CREATE TABLE logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    action VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Sessions table
CREATE TABLE sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    session_id VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Dummy data
INSERT INTO users (username, email, password, role) VALUES
('admin', 'admin@example.com', '$2y$10$e.ZbnWBOzYCBG/hm3RvWxOgyPQVUGiBbAoZ8cQs7E0WBxDqHZQ7t2', 'admin'), -- Password: Majdi@2024
('lawyer1', 'lawyer1@example.com', '$2y$10$e.ZbnWBOzYCBG/hm3RvWxOgyPQVUGiBbAoZ8cQs7E0WBxDqHZQ7t2', 'lawyer'), -- Password: Majdi@2024
('staff1', 'staff1@example.com', '$2y$10$e.ZbnWBOzYCBG/hm3RvWxOgyPQVUGiBbAoZ8cQs7E0WBxDqHZQ7t2', 'staff'), -- Password: Majdi@2024
('finance1', 'finance1@example.com', '$2y$10$e.ZbnWBOzYCBG/hm3RvWxOgyPQVUGiBbAoZ8cQs7E0WBxDqHZQ7t2', 'finance'), -- Password: Majdi@2024
('reception1', 'reception1@example.com', '$2y$10$e.ZbnWBOzYCBG/hm3RvWxOgyPQVUGiBbAoZ8cQs7E0WBxDqHZQ7t2', 'reception'); -- Password: Majdi@2024
