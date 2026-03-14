from flask import Flask
import mysql.connector
import bcrypt

# Database configuration
DATABASE_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': 'Ksksuriya1826',
    'database': 'plastic_cleanup_db'
}

def reset_admin_password():
    try:
        # Create database connection
        connection = mysql.connector.connect(**DATABASE_CONFIG)
        cursor = connection.cursor()
        
        # Admin credentials
        email = 'admin@example.com'
        new_password = 'admin123'  # New password to set
        
        # Hash new password
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        
        # Update admin password
        update_query = """
            UPDATE users 
            SET password = %s 
            WHERE email = %s AND role = 'admin'
        """
        cursor.execute(update_query, (hashed_password.decode('utf-8'), email))
        
        # Commit the transaction
        connection.commit()
        
        if cursor.rowcount > 0:
            print("Admin password reset successfully!")
            print("Email: admin@example.com")
            print("New Password: admin123")
        else:
            print("Admin user not found. Creating new admin user...")
            create_admin_user()
            
    except mysql.connector.Error as error:
        print(f"Failed to reset admin password: {error}")
        
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

def create_admin_user():
    try:
        # Create database connection
        connection = mysql.connector.connect(**DATABASE_CONFIG)
        cursor = connection.cursor()
        
        # Admin credentials
        username = 'Admin'
        email = 'admin@example.com'
        password = 'admin123'
        mobile = '1234567890'
        location = 'Main Office'
        role = 'admin'
        
        # Hash password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        # Insert admin user
        insert_query = """
            INSERT INTO users (username, email, password, mobile, location, role)
            VALUES (%s, %s, %s, %s, %s, %s)
        """
        cursor.execute(insert_query, (
            username,
            email,
            hashed_password.decode('utf-8'),
            mobile,
            location,
            role
        ))
        
        # Commit the transaction
        connection.commit()
        print("Admin user created successfully!")
        print("Email: admin@example.com")
        print("Password: admin123")
        
    except mysql.connector.Error as error:
        print(f"Failed to create admin user: {error}")
        
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

if __name__ == "__main__":
    reset_admin_password()  # This will try to reset password first, if admin doesn't exist, it will create one