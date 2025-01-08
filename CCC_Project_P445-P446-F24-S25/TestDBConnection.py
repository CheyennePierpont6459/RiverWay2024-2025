import MySQLdb

try:
    connection = MySQLdb.connect(
        host="localhost",
        user="root",
        password="Preston-2020",
        database="ccc_emergency_map"
    )
    print("Database connected successfully!")
    cursor = connection.cursor()
    cursor.execute("SHOW TABLES;")
    print(cursor.fetchall())
except MySQLdb.Error as e:
    print(f"Error: {e}")
finally:
    if connection:
        connection.close()
