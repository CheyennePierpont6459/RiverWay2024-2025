-- ============================================
-- 1. Create the Database
-- ============================================

-- Create the database if it doesn't already exist
CREATE DATABASE IF NOT EXISTS ccc_emergency_map;

-- Switch to the newly created database
USE ccc_emergency_map;

-- ============================================
-- 2. Create the Tables
-- ============================================

-- 2.1. Create the users table with is_locked and session_token columns
CREATE TABLE IF NOT EXISTS users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    phone_number VARCHAR(20) NOT NULL,
    account_type VARCHAR(20) DEFAULT 'customer' NOT NULL,
    is_locked BOOLEAN NOT NULL DEFAULT FALSE, -- Existing Column for Account Locking
    session_token VARCHAR(64) DEFAULT NULL, -- New Column for Session Invalidation
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- 2.2. Create the ratings table
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

-- 2.3. Create the emergencies table with assigned_employee_id
CREATE TABLE IF NOT EXISTS emergencies (
    emergency_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    location_details TEXT,
    distress_notes TEXT,
    assigned_employee_id INT DEFAULT NULL, -- New Column for Assigned Employee
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
        ON DELETE CASCADE
        ON UPDATE CASCADE,
    FOREIGN KEY (assigned_employee_id) REFERENCES users(user_id)
        ON DELETE SET NULL
        ON UPDATE CASCADE
) ENGINE=InnoDB;

-- 2.4. Create the chat_messages table
CREATE TABLE IF NOT EXISTS chat_messages (
    message_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    message TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
) ENGINE=InnoDB;

-- 2.5. Create the MFA table
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
-- 3. Create the Stored Procedure
-- ============================================

-- Change the delimiter to allow multi-statement procedure
DELIMITER $$

-- Drop the procedure if it already exists to avoid conflicts
DROP PROCEDURE IF EXISTS DeleteUserAndDependencies$$

-- Create the procedure
CREATE PROCEDURE DeleteUserAndDependencies(IN target_user_id INT)
BEGIN
    -- Declare a handler to catch any SQL exceptions
    DECLARE EXIT HANDLER FOR SQLEXCEPTION
    BEGIN
        ROLLBACK;
        SELECT CONCAT('Error: Failed to delete user with user_id = ', target_user_id, '.') AS Message;
    END;

    -- Start the transaction
    START TRANSACTION;

    -- Delete related records from child tables
    DELETE FROM mfa WHERE user_id = target_user_id;
    DELETE FROM ratings WHERE user_id = target_user_id;
    DELETE FROM emergencies WHERE user_id = target_user_id;
    DELETE FROM chat_messages WHERE user_id = target_user_id;

    -- Delete the user from the parent table
    DELETE FROM users WHERE user_id = target_user_id;

    -- Commit the transaction if all deletions are successful
    COMMIT;

    -- Return a success message
    SELECT CONCAT('Success: User with user_id = ', target_user_id, ' and all related records have been deleted.') AS Message;
END$$

-- Revert the delimiter back to the default
DELIMITER ;

-- ============================================
-- 4. Grant Privileges
-- ============================================

-- Grant all privileges on the ccc_emergency_map database to root@localhost
GRANT ALL PRIVILEGES ON ccc_emergency_map.* TO 'root'@'localhost' WITH GRANT OPTION;

-- Apply the privilege changes
FLUSH PRIVILEGES;