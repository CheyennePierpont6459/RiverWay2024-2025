import mysql.connector
from mysql.connector import errorcode
from flask_sqlalchemy import SQLAlchemy
# Database configuration
db_config = {
    'user': 'root',
    'password': 'Preston-2020',
    'host': 'localhost',
}

# SQL statements
DB_NAME = 'ccc_emergency_map'

TABLES = {
    'users': (
        "CREATE TABLE IF NOT EXISTS users ("
        "  user_id INT AUTO_INCREMENT PRIMARY KEY,"
        "  username VARCHAR(50) NOT NULL,"
        "  email VARCHAR(100) NOT NULL UNIQUE,"
        "  password_hash VARCHAR(255) NOT NULL,"
        "  account_type VARCHAR(20) NOT NULL DEFAULT 'customer',"
        "  created_at DATETIME DEFAULT CURRENT_TIMESTAMP"
        ") ENGINE=InnoDB"
    ),
    'ratings': (
        "CREATE TABLE IF NOT EXISTS ratings ("
        "  rating_id INT AUTO_INCREMENT PRIMARY KEY,"
        "  user_id INT NOT NULL,"
        "  rating_header VARCHAR(100) NOT NULL,"
        "  rating_notes TEXT NOT NULL,"
        "  rating_value INT NOT NULL,"
        "  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,"
        "  FOREIGN KEY (user_id) REFERENCES users(user_id)"
        "    ON DELETE CASCADE"
        "    ON UPDATE CASCADE"
        ") ENGINE=InnoDB"
    ),
    'emergencies': (
        "CREATE TABLE IF NOT EXISTS emergencies ("
        "  emergency_id INT AUTO_INCREMENT PRIMARY KEY,"
        "  user_id INT NOT NULL,"
        "  location_details TEXT,"
        "  distress_notes TEXT,"
        "  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,"
        "  FOREIGN KEY (user_id) REFERENCES users(user_id)"
        "    ON DELETE CASCADE"
        "    ON UPDATE CASCADE"
        ") ENGINE=InnoDB"
    ),
}

def create_database(cursor):
    try:
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DB_NAME} DEFAULT CHARACTER SET 'utf8'")
        print(f"Database '{DB_NAME}' created or already exists.")
    except mysql.connector.Error as err:
        print(f"Failed creating database: {err}")
        exit(1)

def create_tables(cursor):
    cursor.execute(f"USE {DB_NAME}")
    for table_name, table_description in TABLES.items():
        try:
            print(f"Creating table '{table_name}'... ", end='')
            cursor.execute(table_description)

            print("OK")
        except mysql.connector.Error as err:
            if err.errno == errorcode.ER_TABLE_EXISTS_ERROR:
                print("already exists.")
            else:
                print(err.msg)

def main():
    try:
        cnx = mysql.connector.connect(**db_config)
        cursor = cnx.cursor()
        create_database(cursor)
        create_tables(cursor)

        cursor.execute("SHOW DATABASES")
        for db in cursor:
            print(db)
        cursor.close()
        cnx.close()
    except mysql.connector.Error as err:
        print(err)

if __name__ == "__main__":
    main()
