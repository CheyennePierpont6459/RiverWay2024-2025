-- ============================================
-- 1. Create the Database
-- ============================================
CREATE DATABASE IF NOT EXISTS ccc_emergency_map;
USE ccc_emergency_map;

-- ============================================
-- 2. Create the Tables
-- ============================================

-- 2.1. Create the users table (for verified users)
CREATE TABLE IF NOT EXISTS users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    phone_number VARCHAR(20) NOT NULL,
    account_type VARCHAR(20) NOT NULL DEFAULT 'customer',
    is_locked BOOLEAN NOT NULL DEFAULT FALSE,
    session_token VARCHAR(64) DEFAULT NULL UNIQUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    email_verified BOOLEAN NOT NULL DEFAULT TRUE
) ENGINE=InnoDB;

-- 2.2. Create the pending_users table (for new signups pending verification)
CREATE TABLE IF NOT EXISTS pending_users (
    pending_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    email VARCHAR(100) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    phone_number VARCHAR(20) NOT NULL,
    account_type VARCHAR(20) NOT NULL DEFAULT 'customer',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    token VARCHAR(128) NOT NULL UNIQUE,
    token_expiration DATETIME NOT NULL
) ENGINE=InnoDB;

-- 2.3. Create the ratings table
CREATE TABLE IF NOT EXISTS ratings (
    rating_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    rating_header VARCHAR(100) NOT NULL,
    rating_notes TEXT NOT NULL,
    rating_value INT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
) ENGINE=InnoDB;

-- 2.4. Create the emergencies table with an assigned_employee_id column
CREATE TABLE IF NOT EXISTS emergencies (
    emergency_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    location_details TEXT,
    distress_notes TEXT,
    assigned_employee_id INT DEFAULT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
        ON DELETE CASCADE
        ON UPDATE CASCADE,
    FOREIGN KEY (assigned_employee_id) REFERENCES users(user_id)
        ON DELETE SET NULL
        ON UPDATE CASCADE
) ENGINE=InnoDB;

-- 2.5. Create the chat_messages table
CREATE TABLE IF NOT EXISTS chat_messages (
    message_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    message TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
) ENGINE=InnoDB;

-- 2.6. Create the MFA table for multi-factor authentication codes
CREATE TABLE IF NOT EXISTS mfa (
    mfa_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    code VARCHAR(6) NOT NULL,
    expiration DATETIME NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
) ENGINE=InnoDB;

-- ============================================
-- 3. Create the Stored Procedure for Deletion
-- ============================================
DELIMITER $$

DROP PROCEDURE IF EXISTS DeleteUserAndDependencies$$

CREATE PROCEDURE DeleteUserAndDependencies(IN target_user_id INT)
BEGIN
    DECLARE EXIT HANDLER FOR SQLEXCEPTION
    BEGIN
        ROLLBACK;
        SELECT CONCAT('Error: Failed to delete user with user_id = ', target_user_id, '.') AS Message;
    END;

    START TRANSACTION;

    DELETE FROM mfa WHERE user_id = target_user_id;
    DELETE FROM ratings WHERE user_id = target_user_id;
    DELETE FROM emergencies WHERE user_id = target_user_id;
    DELETE FROM chat_messages WHERE user_id = target_user_id;
    -- Optionally, delete any pending record with the same email as the user.
    DELETE FROM pending_users WHERE email = (SELECT email FROM users WHERE user_id = target_user_id);
    DELETE FROM users WHERE user_id = target_user_id;

    COMMIT;
    SELECT CONCAT('Success: User with user_id = ', target_user_id, ' and all related records have been deleted.') AS Message;
END$$

DELIMITER ;

-- ============================================
-- 4. Grant Privileges
-- ============================================
GRANT ALL PRIVILEGES ON ccc_emergency_map.* TO 'root'@'localhost' WITH GRANT OPTION;
FLUSH PRIVILEGES;
