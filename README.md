<h1>100% Secure Login System - PHP</h1>

Majdi M. S.  Awad<br>
Back End Developer<br>
Email: majdiawad.php@gmail.com | Mobile: +971 (055) 993 8785<br>
Linkedin Account: https://www.linkedin.com/in/majdi-awad-aa2384317/<br>
HackerRank Account: https://www.hackerrank.com/profile/majdiawad_php <br>
Abu Dhabi, United Arab Emirates

Abstract

This document provides a comprehensive overview of the Secure Login System, a robust and secure login solution designed primarily for educational purposes. The system aims to demonstrate advanced security measures in web application development. I developed this login system with a focus on ensuring a high level of security, incorporating various mechanisms to protect user data and maintain the integrity of the application.

The system's architecture includes a carefully designed database schema, which features three primary tables: `users`, `logs`, and `sessions`. The `users` table stores essential information about each user, including encrypted passwords, roles, and account status. The `logs` table tracks user actions, IP addresses, and user agents to maintain an audit trail, while the `sessions` table manages active user sessions, including session creation and last activity timestamps.

I wrote the registration script (`registration.php`) to handle user registration, including validation and database insertion. This script ensures that usernames, emails, and passwords are properly validated before creating a new user. The login script (`index.php`) handles user authentication by verifying credentials, managing CSRF tokens to prevent cross-site request forgery attacks, and implementing login attempt limits to protect against brute-force attacks. Upon successful login, users are redirected to an OTP verification page (`otp_verification.php`), where they must enter a one-time password for added security.

The system also includes a `dashboard.php` page, which users access after successful OTP verification. This page provides a secure interface for logged-in users and includes a logout feature to terminate sessions. To further enhance security, I implemented session management practices such as regenerating session IDs upon login and ensuring that sessions are properly terminated upon logout.

The system utilizes environment variables for sensitive configurations such as database credentials and SMTP settings, which are loaded using the Dotenv library. Additionally, I integrated AWS KMS for secure key management and PHPMailer for email functionality, ensuring that OTPs and other critical communications are handled securely.

Overall, this Secure Login System serves as a practical demonstration of implementing comprehensive security measures in a web application, including encryption, session management, OTP verification, and logging.

Total Score: 100/100


