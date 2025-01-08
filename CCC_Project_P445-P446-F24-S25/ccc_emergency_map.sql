-- 1. Create the database if it doesn't already exist
CREATE DATABASE IF NOT EXISTS ccc_emergency_map;

-- 2. Switch to the database
USE ccc_emergency_map;

-- 3. Create the users table
CREATE TABLE IF NOT EXISTS users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    phone_number VARCHAR(20) NOT NULL,
    account_type VARCHAR(20) DEFAULT 'customer' NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 4. Create the ratings table
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
);

-- 5. Create the emergencies table
CREATE TABLE IF NOT EXISTS emergencies (
    emergency_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    location_details TEXT,
    distress_notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
);

-- 6. Create the chat_messages table
CREATE TABLE IF NOT EXISTS chat_messages (
    message_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    message TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
);

-- 7. Create the MFA table
CREATE TABLE IF NOT EXISTS mfa (
    mfa_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    code VARCHAR(6) NOT NULL,
    expiration DATETIME NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
);

-- 8. Use the same database (redundant but safe)
USE ccc_emergency_map;

-- 9. Change the delimiter to allow multi-statement procedure
DELIMITER $$

-- 10. Drop the procedure if it already exists (to avoid conflicts)
DROP PROCEDURE IF EXISTS DeleteUserAndDependencies$$

-- 11. Create the procedure
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

-- 12. Revert the delimiter back to the default
DELIMITER ;

-- 13. Grant all privileges on this DB to root@localhost
GRANT ALL PRIVILEGES ON ccc_emergency_map.* TO 'root'@'localhost' WITH GRANT OPTION;
FLUSH PRIVILEGES;