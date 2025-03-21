-- ============================================
-- 1. Create the Database


-- ============================================
-- 2. Create the Tables
-- ============================================

-- 2.1. Create the users table (for verified users)
CREATE TABLE IF NOT EXISTS users (
    user_id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    phone_number VARCHAR(20) NOT NULL,
    account_type VARCHAR(20) NOT NULL DEFAULT 'customer',
    is_locked BOOLEAN NOT NULL DEFAULT FALSE,
    session_token VARCHAR(64) DEFAULT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    email_verified BOOLEAN NOT NULL DEFAULT TRUE
);

-- 2.2. Create the pending_users table (for new signups pending verification)
CREATE TABLE IF NOT EXISTS pending_users (
    pending_id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    email VARCHAR(100) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    phone_number VARCHAR(20) NOT NULL,
    account_type VARCHAR(20) NOT NULL DEFAULT 'customer',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    token VARCHAR(128) NOT NULL UNIQUE,
    token_expiration TIMESTAMP NOT NULL
);

-- 2.3. Create the ratings table
CREATE TABLE IF NOT EXISTS ratings (
    rating_id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    rating_header VARCHAR(100) NOT NULL,
    rating_notes TEXT NOT NULL,
    rating_value INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_ratings_user FOREIGN KEY (user_id) REFERENCES users(user_id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
);

-- 2.4. Create the emergencies table with an assigned_employee_id column
CREATE TABLE IF NOT EXISTS emergencies (
    emergency_id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    location_details TEXT,
    distress_notes TEXT,
    assigned_employee_id INT DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_emergencies_user FOREIGN KEY (user_id) REFERENCES users(user_id)
        ON DELETE CASCADE
        ON UPDATE CASCADE,
    CONSTRAINT fk_emergencies_employee FOREIGN KEY (assigned_employee_id) REFERENCES users(user_id)
        ON DELETE SET NULL
        ON UPDATE CASCADE
);

-- 2.5. Create the chat_messages table
CREATE TABLE IF NOT EXISTS chat_messages (
    message_id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    message TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_chat_messages_user FOREIGN KEY (user_id) REFERENCES users(user_id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
);

-- 2.6. Create the MFA table for multi-factor authentication codes
CREATE TABLE IF NOT EXISTS mfa (
    mfa_id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    code VARCHAR(6) NOT NULL,
    expiration TIMESTAMP NOT NULL,
    CONSTRAINT fk_mfa_user FOREIGN KEY (user_id) REFERENCES users(user_id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
);

-- ============================================
-- 3. Create the Stored Procedure for Deletion
-- ============================================
-- PostgreSQL uses CREATE OR REPLACE PROCEDURE with PL/pgSQL.
CREATE OR REPLACE PROCEDURE DeleteUserAndDependencies(target_user_id INT)
LANGUAGE plpgsql
AS $$
BEGIN
    DELETE FROM mfa WHERE user_id = target_user_id;
    DELETE FROM ratings WHERE user_id = target_user_id;
    DELETE FROM emergencies WHERE user_id = target_user_id;
    DELETE FROM chat_messages WHERE user_id = target_user_id;
    -- Optionally, delete any pending record with the same email as the user.
    DELETE FROM pending_users
      WHERE email = (SELECT email FROM users WHERE user_id = target_user_id);
    DELETE FROM users WHERE user_id = target_user_id;
    RAISE NOTICE 'Success: User with user_id = % and all related records have been deleted.', target_user_id;
EXCEPTION
    WHEN OTHERS THEN
        RAISE NOTICE 'Error: Failed to delete user with user_id = %.', target_user_id;
        RAISE;
END;
$$;

-- ============================================
-- 4. Grant Privileges
-- ============================================
-- In PostgreSQL, granting privileges is done differently.
-- For example, to grant all privileges on the database to a specific user (e.g., postgres):
GRANT ALL PRIVILEGES ON DATABASE cave_country_canoes TO postgres;

-- Optionally, to grant privileges on all tables in the public schema:
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO postgres;
