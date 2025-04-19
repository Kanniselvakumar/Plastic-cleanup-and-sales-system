from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
import mysql.connector
from mysql.connector import Error
import bcrypt
import os
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import requests 
from functools import wraps
import logging
import traceback
from decimal import Decimal
from flask_mail import Mail, Message
import secrets
import pandas as pd
import xgboost as xgb
import numpy as np
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
import joblib

app = Flask(__name__)
app.secret_key = 'your_secret_key'

mail = Mail()

# Register the donation blueprint
#app.register_blueprint(donation_bp)

# Database configuration
DATABASE_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': 'Ksksuriya1826',
    'database': 'plastic_cleanup_db'
}


def init_mail(app):
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = 'kanniselvakumar@gmail.com'
    app.config['MAIL_PASSWORD'] = 'ebae tmef whzc xytb'
    mail.init_app(app)

init_mail(app)

# File upload settings
NOMINATIM_URL = "https://nominatim.openstreetmap.org/reverse"
UPLOAD_FOLDER = 'static/uploads/'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# Create uploads directory if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def create_connection():
    try:
        connection = mysql.connector.connect(**DATABASE_CONFIG)
        return connection
    except Error as e:
        print(f"Error connecting to MySQL: {e}")
        return None
    

@app.route('/')
def home():
    connection = create_connection()
    try:
        cursor = connection.cursor(dictionary=True)
        
        # Modified query to correctly calculate impact stats
        cursor.execute("""
            SELECT 
                COUNT(DISTINCT e.id) as total_events,
                COUNT(DISTINCT ev.volunteer_id) as total_volunteers,
                COALESCE(SUM(ev.plastics_collected), 0) as total_plastics,
                (
                    SELECT COALESCE(SUM(products_recycled), 0)
                    FROM events 
                    WHERE status = 'Completed'
                ) as total_products
            FROM events e
            LEFT JOIN event_volunteers ev ON e.id = ev.event_id
            WHERE e.status = 'Completed'
        """)
        impact_stats = cursor.fetchone()
        
        # Add debugging log
        print("Impact Stats:", impact_stats)
        
        # Query to fetch top volunteers (remains unchanged)
        cursor.execute("""
            SELECT 
                u.username AS name,
                u.location,
                COALESCE(SUM(ev.plastics_collected), 0) AS plastics_collected,
                COUNT(ev.event_id) AS events_participated
            FROM event_volunteers ev
            JOIN users u ON ev.volunteer_id = u.id
            JOIN events e ON ev.event_id = e.id
            WHERE e.status = 'Completed'
            GROUP BY u.id, u.username, u.location
            ORDER BY plastics_collected DESC
            LIMIT 10
        """)
        top_volunteers = cursor.fetchall()
        
        # Handle null locations
        for volunteer in top_volunteers:
            if not volunteer.get('location'):
                volunteer['location'] = 'Location unavailable'

        cursor.execute("""
            SELECT p.*, u.username as organiser_name 
            FROM products p
            JOIN users u ON p.organiser_id = u.id
            WHERE p.status = 'Approved'
            ORDER BY RAND()  # Randomly select products
            LIMIT 8  # Show 8 featured products
        """)
        featured_products = cursor.fetchall()
        
        # Process product data
        for product in featured_products:
            # Format price
            product['formatted_price'] = f"₹{float(product['price']):.2f}"
            
            # Format quantity and stock status
            if product['quantity'] is None:
                product['stock_status'] = 'out-of-stock'
                product['stock_text'] = 'Out of Stock'
            elif float(product['quantity']) == 0:
                product['stock_status'] = 'out-of-stock'
                product['stock_text'] = 'Out of Stock'
            elif float(product['quantity']) < 10:
                product['stock_status'] = 'low-stock'
                product['stock_text'] = 'Low Stock'
            else:
                product['stock_status'] = 'in-stock'
                product['stock_text'] = 'In Stock'
            
            # Set product image URL
            if product['image_path']:
                product['image_url'] = url_for('static', filename=f'uploads/{product["image_path"]}')
            else:
                product['image_url'] = url_for('static', filename='default-product.jpg')        
        
        return render_template('home.html',
                             impact_stats=impact_stats,
                             top_volunteers=top_volunteers,
                             featured_products=featured_products)
                             
    except Error as e:
        print(f"Database error: {e}")
        return str(e), 500
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()



# Admin authentication decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'admin':
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# Add these routes to your Flask application

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        connection = create_connection()
        if connection is None:
            return render_template('admin/login.html', error="Database connection failed.")

        try:
            cursor = connection.cursor(dictionary=True)
           
            # Add debug logging
            print(f"Attempting login for email: {email}")
           
            cursor.execute("SELECT * FROM users WHERE email = %s AND role = 'admin'", (email,))
            admin = cursor.fetchone()
           
            if admin:
                print("Found admin user in database")
                try:
                    # Ensure the stored password is properly encoded
                    stored_password = admin['password']
                    if isinstance(stored_password, str):
                        stored_password = stored_password.encode('utf-8')
                   
                    # Ensure the input password is properly encoded
                    if isinstance(password, str):
                        password = password.encode('utf-8')
                   
                    # Check password
                    if bcrypt.checkpw(password, stored_password):
                        print("Password check successful")
                        session['user_id'] = admin['id']
                        session['username'] = admin['username']
                        session['role'] = admin['role']
                        return redirect(url_for('admin_dashboard'))
                    else:
                        print("Password check failed")
                except Exception as e:
                    print(f"Password checking error: {e}")
                    return render_template('admin/login.html', error="An error occurred during login.")
            else:
                print("No admin user found with provided email")
           
            return render_template('admin/login.html', error="Invalid credentials.")

        except Error as e:
            print(f"Database error: {e}")
            return render_template('admin/login.html', error="Login failed.")
        finally:
            if connection.is_connected():
                cursor.close()
                connection.close()

    return render_template('admin/login.html')

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    connection = create_connection()
    try:
        cursor = connection.cursor(dictionary=True)

        # Fetch statistics with correct plastics_collected calculation
        cursor.execute("""
            SELECT 
                (SELECT COUNT(*) FROM users WHERE role = 'organiser') AS organiser_count,
                (SELECT COUNT(*) FROM users WHERE role = 'volunteer') AS volunteer_count,
                (SELECT COUNT(*) FROM events) AS event_count,
                (SELECT COUNT(*) FROM events WHERE status = 'Completed') AS completed_events,
                (SELECT COALESCE(SUM(ev.plastics_collected), 0) FROM (
                    SELECT event_id, SUM(plastics_collected) AS plastics_collected
                    FROM event_volunteers
                    GROUP BY event_id
                ) ev) AS total_plastics_collected,
                (SELECT COALESCE(SUM(amount), 0) FROM donations) AS total_donations
        """)
        stats = cursor.fetchone()

        # Convert Decimal values to float for JSON-safe rendering
        stats['total_plastics_collected'] = float(stats['total_plastics_collected'])
        stats['total_donations'] = float(stats['total_donations'])

        # Fetch recent activities
        cursor.execute("""
            (SELECT 'New User' AS type, username AS name, created_at AS date
             FROM users 
             WHERE created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY))
            UNION ALL
            (SELECT 'New Event' AS type, event_name AS name, event_date AS date
             FROM events 
             WHERE event_date >= DATE_SUB(NOW(), INTERVAL 30 DAY))
            UNION ALL
            (SELECT 'New Donation' AS type, donor_name AS name, donation_date AS date
             FROM donations 
             WHERE donation_date >= DATE_SUB(NOW(), INTERVAL 30 DAY))
            ORDER BY date DESC
            LIMIT 10
        """)
        recent_activities = cursor.fetchall()


        return render_template('admin/dashboard.html', 
                               stats=stats,
                               recent_activities=recent_activities)

    except Error as e:
        print(f"Database error: {e}")
        return str(e), 500

    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()





@app.route('/admin/users')
@admin_required
def admin_users():
    connection = create_connection()
    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("""
            SELECT id, username, email, mobile, location, role, created_at,
            CASE 
                WHEN role = 'organiser' THEN (
                    SELECT COUNT(*) FROM events WHERE organiser_id = users.id
                )
                WHEN role = 'volunteer' THEN (
                    SELECT COUNT(*) FROM event_volunteers WHERE volunteer_id = users.id
                )
                ELSE 0
            END as activity_count
            FROM users
            ORDER BY created_at DESC
        """)
        users = cursor.fetchall()

        # Convert location coordinates to readable format
        for user in users:
            user['location'] = get_human_readable_location(user['location'])

        return render_template('admin/users.html', users=users)
    
    except Exception as e:
        print(f"Error fetching users: {e}")
        return str(e), 500

    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()
@app.route('/admin/users/delete/<int:user_id>', methods=['DELETE'])
@admin_required
def delete_user(user_id):
    connection = create_connection()
    try:
        cursor = connection.cursor()

        # Step 1: Delete related records in purchase_history
        cursor.execute("DELETE FROM purchase_history WHERE user_id = %s", (user_id,))

        # Step 2: Delete user
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        connection.commit()

        return jsonify({'message': 'User deleted successfully'}), 200
    except mysql.connector.Error as e:
        print(f"Error deleting user: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        connection.close()
         

@app.route('/admin/user/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_user(user_id):
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        mobile = request.form.get('mobile')
        location = request.form.get('location')
        role = request.form.get('role')
        
        connection = create_connection()
        try:
            cursor = connection.cursor()
            cursor.execute("""
                UPDATE users 
                SET username = %s, email = %s, mobile = %s, location = %s, role = %s
                WHERE id = %s
            """, (username, email, mobile, location, role, user_id))
            connection.commit()
            flash('User updated successfully', 'success')
            return redirect(url_for('admin_users'))
        finally:
            if connection and connection.is_connected():
                cursor.close()
                connection.close()
    
    connection = create_connection()
    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        return render_template('admin/edit_user.html', user=user)
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.route('/admin/events')
@admin_required
def admin_events():
    connection = create_connection()
    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("""
            SELECT e.*, u.username AS organiser_name,
                   COUNT(ev.id) AS volunteer_count
            FROM events e
            LEFT JOIN users u ON e.organiser_id = u.id
            LEFT JOIN event_volunteers ev ON e.id = ev.event_id
            GROUP BY e.id
            ORDER BY 
                CASE 
                    WHEN e.status = 'Upcoming' THEN 1
                    WHEN e.status = 'Active' THEN 2
                    WHEN e.status = 'Completed' THEN 3
                    ELSE 4
                END,
                e.event_date DESC
        """)
        events = cursor.fetchall()
        return render_template('admin/events.html', events=events)
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()
@app.route('/admin/delete_event/<int:event_id>', methods=['POST'])
@admin_required
def admin_delete_event(event_id):
    """Delete an event and associated data."""
    connection = create_connection()
    try:
        cursor = connection.cursor()
        
        # Delete related event data first (volunteers, feedback, etc.)
        cursor.execute("DELETE FROM event_feedback WHERE event_id = %s", (event_id,))
        cursor.execute("DELETE FROM event_volunteers WHERE event_id = %s", (event_id,))
        
        # Delete the event itself
        cursor.execute("DELETE FROM events WHERE id = %s", (event_id,))
        
        connection.commit()
        flash('Event deleted successfully', 'success')
        return redirect(url_for('admin_events'))

    except Exception as e:
        print(f"Error deleting event: {e}")
        flash('An error occurred while deleting the event.', 'error')
        return redirect(url_for('admin_events'))

    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.route('/admin/donations')
@admin_required
def admin_donations():
    connection = None
    try:
        connection = create_connection()
        cursor = connection.cursor(dictionary=True)

        # Default values for filters
        selected_organiser = request.args.get('organiser', '')
        start_date = request.args.get('start_date', '')
        end_date = request.args.get('end_date', '')

        # Base query with dynamic filtering
        query = """
            SELECT d.*, COALESCE(u.username, 'Unknown') as organiser_name
            FROM donations d
            LEFT JOIN users u ON d.organiser_id = u.id
        """

        # Build where clause dynamically
        conditions = []
        params = []

        if selected_organiser:
            conditions.append("u.username = %s")
            params.append(selected_organiser)

        if start_date:
            conditions.append("d.donation_date >= %s")
            params.append(start_date)

        if end_date:
            conditions.append("d.donation_date <= %s")
            params.append(end_date)

        # Add WHERE clause if conditions exist
        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        # Add sorting
        query += " ORDER BY d.donation_date DESC"

        # Execute query
        cursor.execute(query, params)
        donations = cursor.fetchall()

        # Get unique organisers
        cursor.execute("SELECT DISTINCT username FROM users WHERE role = 'organiser'")
        organisers = [org['username'] for org in cursor.fetchall()]

        # Calculate total donations
        total_donations = sum(donation['amount'] for donation in donations) if donations else 0

        return render_template('admin/donations.html',
                               donations=donations or [],
                               organisers=organisers,
                               selected_organiser=selected_organiser,
                               start_date=start_date,
                               end_date=end_date,
                               total_donations=total_donations)

    except Exception as e:
        app.logger.error(f"Donations Error: {str(e)}")
        flash('Error fetching donations', 'error')
        return redirect(url_for('admin_dashboard'))

    finally:
        if connection and connection.is_connected():
            connection.close()
@app.route('/admin/reports')
@admin_required
def admin_reports():
    connection = create_connection()
    try:
        cursor = connection.cursor(dictionary=True)

        # Get monthly statistics (Ensuring correct sum of products_recycled)
        cursor.execute("""
            SELECT 
                DATE_FORMAT(e.event_date, '%Y-%m') AS month,
                COUNT(DISTINCT CASE WHEN e.status = 'Completed' THEN e.id END) AS event_count,
                COALESCE(SUM(ev.plastics_collected), 0) AS plastics_collected,
                COALESCE(SUM(DISTINCT e.products_recycled), 0) AS total_products_recycled
            FROM events e
            LEFT JOIN (
                SELECT event_id, SUM(plastics_collected) AS plastics_collected
                FROM event_volunteers
                GROUP BY event_id
            ) ev ON e.id = ev.event_id
            WHERE e.status = 'Completed'
            GROUP BY DATE_FORMAT(e.event_date, '%Y-%m')
            ORDER BY month DESC
            LIMIT 12
        """)
        monthly_stats = cursor.fetchall()

        # Get top organizers with correctly summed products recycled
        cursor.execute("""
            SELECT 
                u.username,
                COUNT(DISTINCT CASE WHEN e.status = 'Completed' THEN e.id END) AS event_count,
                COALESCE(SUM(ev.plastics_collected), 0) AS total_plastics,
                COALESCE(SUM(DISTINCT e.products_recycled), 0) AS total_products_recycled
            FROM users u
            LEFT JOIN events e ON u.id = e.organiser_id
            LEFT JOIN (
                SELECT event_id, SUM(plastics_collected) AS plastics_collected
                FROM event_volunteers
                GROUP BY event_id
            ) ev ON e.id = ev.event_id
            WHERE u.role = 'organiser'
            GROUP BY u.id, u.username
            ORDER BY total_products_recycled DESC
            LIMIT 10
        """)
        top_organizers = cursor.fetchall()

        return render_template('admin/reports.html',
                               monthly_stats=monthly_stats,
                               top_organizers=top_organizers)
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()



@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    connection = create_connection()
    try:
        cursor = connection.cursor()
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        connection.commit()
        flash('User deleted successfully', 'success')
        return redirect(url_for('admin_users'))
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.route('/admin/system-settings', methods=['GET', 'POST'])
@admin_required
def admin_system_settings():
    if request.method == 'POST':
        # Handle system settings updates
        settings = {
            'site_name': request.form.get('site_name'),
            'contact_email': request.form.get('contact_email'),
            'maintenance_mode': request.form.get('maintenance_mode') == 'on'
        }
        
        connection = create_connection()
        try:
            cursor = connection.cursor()
            for key, value in settings.items():
                cursor.execute("""
                    INSERT INTO system_settings (setting_key, setting_value)
                    VALUES (%s, %s)
                    ON DUPLICATE KEY UPDATE setting_value = %s
                """, (key, str(value), str(value)))
            connection.commit()
            flash('Settings updated successfully', 'success')
        finally:
            if connection and connection.is_connected():
                cursor.close()
                connection.close()
                
    # Fetch current settings
    connection = create_connection()
    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM system_settings")
        settings = {row['setting_key']: row['setting_value'] for row in cursor.fetchall()}
        return render_template('admin/settings.html', settings=settings)
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.route('/admin/buyers')
@admin_required
def admin_buyers():
    """Fetch buyer details for admin."""
    connection = create_connection()
    try:
        cursor = connection.cursor(dictionary=True)

        # Query to fetch buyer details
        cursor.execute("""
            SELECT 
                u.id AS buyer_id,         
                u.username AS buyer_name,
                u.email AS buyer_email,
                u.mobile AS buyer_mobile,
                ph.product_name,
                ph.price,
                ph.purchase_date,
                ph.status
            FROM purchase_history ph
            JOIN users u ON ph.user_id = u.id
            WHERE ph.status = 'Completed'
            ORDER BY ph.purchase_date DESC
        """)
        buyers = cursor.fetchall()

        return render_template('admin/buyers.html', buyers=buyers)

    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.route('/admin/delete_buyer/<int:user_id>', methods=['POST'])
@admin_required
def admin_delete_buyer(user_id):
    """Delete a buyer record."""
    connection = create_connection()
    try:
        cursor = connection.cursor()

        # Delete purchases before deleting buyer to maintain referential integrity
        cursor.execute("DELETE FROM purchase_history WHERE user_id = %s", (user_id,))
        cursor.execute("DELETE FROM users WHERE id = %s AND role = 'buyer'", (user_id,))
        
        connection.commit()
        flash('Buyer deleted successfully', 'success')
        return redirect(url_for('admin_buyers'))

    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        
        connection = create_connection()
        if connection is None:
            flash('Database connection failed.', 'error')
            return render_template('forgot_password.html')
            
        try:
            cursor = connection.cursor(dictionary=True)
            
            # Check if email exists
            cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()
            
            if user:
                # Generate reset token
                reset_token = secrets.token_urlsafe(32)
                expiration = datetime.now() + timedelta(hours=1)

                
                # Store reset token in database
                cursor.execute("""
                    UPDATE users 
                    SET reset_token = %s, reset_token_expiry = %s 
                    WHERE email = %s
                """, (reset_token, expiration, email))
                connection.commit()
                
                # Send reset email
                reset_url = url_for('reset_password', token=reset_token, _external=True)
                msg = Message(
                    'Password Reset Request',
                    sender='kanniselvakumar@gmail.com',
                    recipients=[email]
                )
                msg.body = f'''To reset your password, visit the following link:
{reset_url}

If you did not make this request, please ignore this email.
The link will expire in 1 hour.
'''
                mail.send(msg)
                
                flash('Reset instructions sent to your email.', 'success')
                return redirect(url_for('login'))
            else:
                flash('Email address not found.', 'error')
                
        except Error as e:
            print(f"Database error: {e}")
            flash('An error occurred. Please try again.', 'error')
        finally:
            if connection.is_connected():
                cursor.close()
                connection.close()
                
    return render_template('forgot_password.html')

# Route for reset password page
@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    connection = create_connection()
    if connection is None:
        flash('Database connection failed.', 'error')
        return redirect(url_for('login'))
        
    try:
        cursor = connection.cursor(dictionary=True)
        
        # Verify token and check expiration
        cursor.execute("""
            SELECT id FROM users 
            WHERE reset_token = %s AND reset_token_expiry > NOW()
        """, (token,))
        user = cursor.fetchone()
        
        if not user:
            flash('Invalid or expired reset link.', 'error')
            return redirect(url_for('login'))
            
        if request.method == 'POST':
            password = request.form['password']
            confirm_password = request.form['confirm_password']
            
            if password != confirm_password:
                flash('Passwords do not match.', 'error')
                return render_template('reset_password.html')
                
            # Update password and clear reset token
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            cursor.execute("""
                UPDATE users 
                SET password = %s, reset_token = NULL, reset_token_expiry = NULL 
                WHERE id = %s
            """, (hashed_password.decode('utf-8'), user['id']))
            connection.commit()
            
            flash('Password has been reset successfully.', 'success')
            return redirect(url_for('login'))
            
    except Error as e:
        print(f"Database error: {e}")
        flash('An error occurred. Please try again.', 'error')
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()
            
    return render_template('reset_password.html')  

def json_serial(obj):
    """JSON serializer for objects not serializable by default json code"""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")

# API endpoint for Power BI to consume dashboard statistics
@app.route('/api/dashboard-stats', methods=['GET'])
@admin_required
def dashboard_stats_api():
    connection = create_connection()
    try:
        cursor = connection.cursor(dictionary=True)

        # Fetch the same statistics used in the admin dashboard
        cursor.execute("""
            SELECT 
                (SELECT COUNT(*) FROM users WHERE role = 'organiser') AS organiser_count,
                (SELECT COUNT(*) FROM users WHERE role = 'volunteer') AS volunteer_count,
                (SELECT COUNT(*) FROM events) AS event_count,
                (SELECT COUNT(*) FROM events WHERE status = 'Completed') AS completed_events,
                (SELECT COALESCE(SUM(ev.plastics_collected), 0) FROM (
                    SELECT event_id, SUM(plastics_collected) AS plastics_collected
                    FROM event_volunteers
                    GROUP BY event_id
                ) ev) AS total_plastics_collected,
                (SELECT COALESCE(SUM(amount), 0) FROM donations) AS total_donations
        """)
        stats = cursor.fetchone()

        # Convert Decimal values to float for JSON-safe rendering
        stats['total_plastics_collected'] = float(stats['total_plastics_collected'])
        stats['total_donations'] = float(stats['total_donations'])
        
        return jsonify(stats)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

# API endpoint for monthly statistics 
@app.route('/api/monthly-stats', methods=['GET'])
@admin_required
def monthly_stats_api():
    connection = create_connection()
    try:
        cursor = connection.cursor(dictionary=True)

        # Get monthly statistics
        cursor.execute("""
            SELECT 
                DATE_FORMAT(e.event_date, '%Y-%m') AS month,
                COUNT(DISTINCT CASE WHEN e.status = 'Completed' THEN e.id END) AS event_count,
                COALESCE(SUM(ev.plastics_collected), 0) AS plastics_collected,
                COALESCE(SUM(DISTINCT e.products_recycled), 0) AS total_products_recycled
            FROM events e
            LEFT JOIN (
                SELECT event_id, SUM(plastics_collected) AS plastics_collected
                FROM event_volunteers
                GROUP BY event_id
            ) ev ON e.id = ev.event_id
            WHERE e.status = 'Completed'
            GROUP BY DATE_FORMAT(e.event_date, '%Y-%m')
            ORDER BY month DESC
            LIMIT 12
        """)
        monthly_stats = cursor.fetchall()
        
        # Convert to JSON-serializable format
        result = json.loads(json.dumps(monthly_stats, default=json_serial))
        
        return jsonify(result)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

# API endpoint for top organizers
@app.route('/api/top-organizers', methods=['GET'])
@admin_required
def top_organizers_api():
    connection = create_connection()
    try:
        cursor = connection.cursor(dictionary=True)

        # Get top organizers
        cursor.execute("""
            SELECT 
                u.username,
                COUNT(DISTINCT CASE WHEN e.status = 'Completed' THEN e.id END) AS event_count,
                COALESCE(SUM(ev.plastics_collected), 0) AS total_plastics,
                COALESCE(SUM(DISTINCT e.products_recycled), 0) AS total_products_recycled
            FROM users u
            LEFT JOIN events e ON u.id = e.organiser_id
            LEFT JOIN (
                SELECT event_id, SUM(plastics_collected) AS plastics_collected
                FROM event_volunteers
                GROUP BY event_id
            ) ev ON e.id = ev.event_id
            WHERE u.role = 'organiser'
            GROUP BY u.id, u.username
            ORDER BY total_products_recycled DESC
            LIMIT 10
        """)
        top_organizers = cursor.fetchall()
        
        # Convert to JSON-serializable format
        result = json.loads(json.dumps(top_organizers, default=json_serial))
        
        return jsonify(result)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

# API endpoint for donations data
@app.route('/api/donations', methods=['GET'])
@admin_required
def donations_api():
    connection = create_connection()
    try:
        cursor = connection.cursor(dictionary=True)

        # Get donations data
        cursor.execute("""
            SELECT 
                d.id,
                d.donor_name,
                d.amount,
                d.donation_date,
                COALESCE(u.username, 'Unknown') as organiser_name
            FROM donations d
            LEFT JOIN users u ON d.organiser_id = u.id
            ORDER BY d.donation_date DESC
        """)
        donations = cursor.fetchall()
        
        # Convert to JSON-serializable format
        result = json.loads(json.dumps(donations, default=json_serial))
        
        return jsonify(result)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

# Add a Power BI dashboard integration page to your admin interface
@app.route('/admin/powerbi-dashboard')
@admin_required
def admin_powerbi_dashboard():
    # This template will contain the embedded Power BI dashboard
    return render_template('admin/powerbi_dashboard.html')    



@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        mobile = request.form['mobile']
        location = request.form['location']
        role = request.form['role']

        if not all([username, password, email, mobile, location, role]):
            return render_template(
                'register.html',
                error="All fields are required.",
                username=username, email=email, mobile=mobile, location=location, role=role
            )

        connection = create_connection()
        if connection is None:
            return render_template('register.html', error="Database connection failed.")

        try:
            cursor = connection.cursor(dictionary=True)
            
            # Check for existing email
            cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
            if cursor.fetchone():
                return render_template(
                    'register.html',
                    error="Email already exists.",
                    username=username, mobile=mobile, location=location, role=role
                )

            # Hash password
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

            # Insert user
            insert_query = """
                INSERT INTO users (username, password, email, mobile, location, role) 
                VALUES (%s, %s, %s, %s, %s, %s)
            """
            cursor.execute(insert_query, (
                username, 
                hashed_password.decode('utf-8'), 
                email, 
                mobile, 
                location, 
                role
            ))
            connection.commit()
            
            #flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))

        except Error as e:
            print(f"Database error: {e}")
            return render_template('register.html', error="Registration failed.")
        finally:
            if connection.is_connected():
                cursor.close()
                connection.close()

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        connection = create_connection()
        if connection is None:
            return render_template('login.html', error="Database connection failed.")

        try:
            cursor = connection.cursor(dictionary=True)
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()

            if user:
                # Ensure password is a string before encoding
                password = str(password)

                # Ensure the stored password is bytes (bcrypt requires bytes for comparison)
                stored_password = user['password']
                # Convert stored password to string before encoding if it’s not already bytes
                if isinstance(stored_password, str):  
                    stored_password = stored_password.encode('utf-8')  # ✅ Convert stored hash to bytes

                # Ensure input password is bytes
                password = password.encode('utf-8')
                # Now check the password
                if bcrypt.checkpw(password, stored_password):
                    session['user_id'] = user['id']
                    session['username'] = user['username']
                    session['role'] = user['role']
                    session['email'] = user['email']
                    session['mobile'] = user['mobile']
                    session['location'] = user['location']

                    if user['role'] == 'organiser':
                        return redirect(url_for('organiser'))
                    elif user['role'] == 'volunteer':
                        return redirect(url_for('volunteer'))
                    elif user['role'] in ['buyer', 'other']:
                        print("Attempting to redirect to sales page")
                        return redirect(url_for('sales'))
            return render_template('login.html', error="Invalid credentials.")

        except Error as e:
            print(f"Database error: {e}")
            return render_template('login.html', error="Login failed.")
        finally:
            if connection.is_connected():
                cursor.close()
                connection.close()

    return render_template('login.html')


@app.route('/organiser', methods=['GET', 'POST'])
def organiser():
    if 'user_id' not in session or session.get('role') != 'organiser':
        return redirect(url_for('login'))

    connection = create_connection()
    if connection is None:
        flash('Database connection failed.', 'error')
        return redirect(url_for('login'))

    try:
        cursor = connection.cursor(dictionary=True)
        user = {
            'id': session.get('user_id'),
            'username': session.get('username'),
            'email': session.get('email'),
            'mobile': session.get('mobile'),
            'location': session.get('location'),
            'role': session.get('role')
        }


        cursor.execute("""
            SELECT username, email, mobile, location 
            FROM users 
            WHERE id = %s
        """, (session['user_id'],))
        user_data = cursor.fetchone()

        if not user_data:
            flash('User profile not found.', 'error')
            return redirect(url_for('login'))

        cursor.execute("""
            SELECT e.*,
            COALESCE(e.status, 
                CASE 
                    WHEN event_date > CURDATE() THEN 'Upcoming'
                    WHEN event_date = CURDATE() THEN 'Active'
                    ELSE 'Completed'
                END
            ) as status,
            COUNT(ev.id) as joined_volunteers
            FROM events e
            LEFT JOIN event_volunteers ev ON e.id = ev.event_id
            WHERE e.organiser_id = %s 
            GROUP BY e.id
            ORDER BY e.event_date DESC
        """, (session['user_id'],))
        events = cursor.fetchall()

        if request.method == 'POST':
            if 'create-event' in request.form:
                event_name = request.form.get('event-name')
                event_date = request.form.get('event-date')
                event_time = request.form.get('event-time')
                latitude = request.form.get('latitude')
                longitude = request.form.get('longitude')
                volunteers = request.form.get('volunteers')
                volunteer_salary = request.form.get('volunteer-salary')
                supplies = ','.join(request.form.getlist('supplies[]'))
                
                photo_path = None
                if 'event-photo' in request.files:
                    file = request.files['event-photo']
                    if file and allowed_file(file.filename):
                        filename = secure_filename(file.filename)
                        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                        photo_path = filename

                cursor.execute("""
                    INSERT INTO events (
                        organiser_id, event_name, event_date, event_time, 
                        latitude, longitude, num_volunteers, 
                        salary_per_volunteer, photo_path, supplies, status
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s,'Upcoming')
                """, (
                    session['user_id'], event_name, event_date, event_time, 
                    latitude, longitude,volunteers, 
                    volunteer_salary, photo_path, supplies
                ))
                connection.commit()
                return jsonify({'success': True, 'message': 'Event created successfully!'})

            elif request.form.get('action') == 'edit_event':
                event_id = request.form.get('event_id')
                event_name = request.form.get('event-name')
                event_date = request.form.get('event-date')
                event_time = request.form.get('event-time')
                volunteers = request.form.get('volunteers')
                volunteer_salary = request.form.get('volunteer-salary')
                event_status = request.form.get('event-status')
                
                connection = create_connection()
                if not connection:
                    return jsonify({'success': False, 'message': 'Database connection failed'})
                cursor = connection.cursor(dictionary=True)
                cursor.execute("""
                    UPDATE events 
                    SET event_name = %s, 
                        event_date = %s, 
                        event_time = %s, 
                        num_volunteers = %s,
                        salary_per_volunteer = %s,
                        status = %s
                    WHERE id = %s AND organiser_id = %s
                """, (event_name, event_date, event_time, volunteers, volunteer_salary, event_status, event_id, session['user_id']))
                connection.commit()
                if cursor.rowcount > 0:
                    return jsonify({
                        'success': True, 
                        'message': 'Event updated successfully!'
                    })
                else:
                    return jsonify({
                       'success': False, 
                        'message': 'No event was updated. Please check the event ID.'
                    })

            elif request.form.get('action') == 'delete_event':
                try:
                    event_id = request.form.get('event_id')
                
                # Start a transaction
                    cursor.execute("START TRANSACTION")
                    cursor.execute("DELETE FROM volunteer_badges WHERE event_id = %s", (event_id,))
                # Delete from event_feedback first
                    cursor.execute("DELETE FROM event_feedback WHERE event_id = %s", (event_id,))
                
                # Delete from event_volunteers next
                    cursor.execute("DELETE FROM event_volunteers WHERE event_id = %s", (event_id,))
                
                # Finally, delete the event itself
                    cursor.execute("DELETE FROM events WHERE id = %s AND organiser_id = %s", 
                             (event_id, session['user_id']))
                
                # Commit the transaction
                    connection.commit()
                    return jsonify({'success': True, 'message': 'Event deleted successfully!'})
                
                except Error as e:
                    # Rollback in case of error
                    connection.rollback()
                    print(f"Database error: {e}")
                    return jsonify({'success': False, 'message': str(e)}), 500
        
        cursor.execute("""
            SELECT 
                u.id AS buyer_id,
                u.username AS buyer_name,
                u.email AS buyer_email,
                u.mobile AS buyer_mobile,
                ph.product_name,
                ph.price,
                ph.quantity,
                ph.purchase_date
            FROM purchase_history ph
            JOIN users u ON ph.user_id = u.id
            JOIN products p ON ph.product_id = p.id
            WHERE p.organiser_id = %s
        """, (session['user_id'],))
        buyers = cursor.fetchall()
        feedbacks = cursor.fetchall()
        buyers=buyers

        cursor.execute("""
            SELECT 
                donor_name,
                donor_email,
                amount,
                donation_date,
                status
            FROM donations 
            WHERE organiser_id = %s
            ORDER BY donation_date DESC
        """, (session['user_id'],))
        donors = cursor.fetchall()

        # Create user dictionary with all necessary data
        

        if request.method == 'POST':
            # Your existing POST handling code here
            pass

        return render_template('organiser.html', 
                             user=user,  # Pass the complete user dictionary
                             events=events,
                             feedbacks=feedbacks, buyers=buyers,donors=donors)
                             
    except Error as e:
        print(f"Database error: {e}")
        buyers = []  # Initialize buyers to an empty list if an error occurs
        user = {}
        events = []
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.route('/admin/products')
@admin_required
def admin_products():
    connection = create_connection()
    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM products WHERE status = 'Pending'")
        products = cursor.fetchall()
        return render_template('admin/products.html', products=products)
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

@app.route('/admin/approve_product/<int:product_id>', methods=['POST'])
@admin_required
def approve_product(product_id):
    connection = create_connection()
    try:
        cursor = connection.cursor()
        status = request.form.get('status')
        cursor.execute("UPDATE products SET status = %s WHERE id = %s", (status, product_id))
        connection.commit()
        flash('Product status updated successfully!', 'success')
        return redirect(url_for('admin_products'))
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()  

@app.route('/volunteer', methods=['GET', 'POST'])
def volunteer():
    if 'user_id' not in session or session.get('role') != 'volunteer':
        return redirect(url_for('login'))

    connection = create_connection()
    if connection is None:
        flash('Database connection failed.', 'error')
        return redirect(url_for('login'))

    try:
        cursor = connection.cursor(dictionary=True)

        # Fetch all events with latitude and longitude
        cursor.execute("""
            SELECT e.*, u.username AS organiser_name,
                COUNT(ev.id) as joined_volunteers,
                EXISTS(
                    SELECT 1 FROM event_volunteers 
                    WHERE event_id = e.id AND volunteer_id = %s
                ) as is_joined     
            FROM events e
            JOIN users u ON e.organiser_id = u.id
            LEFT JOIN event_volunteers ev ON e.id = ev.event_id
            WHERE e.event_date >= CURDATE()
            GROUP BY e.id
            ORDER BY e.event_date ASC
        """, (session['user_id'],))
        events = cursor.fetchall()
        # Convert latitude and longitude to human-readable location names directly here
        for event in events:
            try:
                params = {
                    'lat': event['latitude'],
                    'lon': event['longitude'],
                    'format': 'json'
                }
                headers = {'User-Agent': 'PlasticCleanupApp/1.0'}
                response = requests.get(NOMINATIM_URL, params=params, headers=headers)
                response.raise_for_status()
                
                location_data = response.json()
                event['location'] = location_data.get('display_name', 'Location unavailable')
                
            except Exception as e:
                print(f"Location fetch error for Event {event['id']}: {e}")
                event['location'] = 'Location unavailable'

        if request.method == 'POST':
            if 'join_event' in request.form:
                event_id = request.form.get('event_id')

                # Check if volunteer has already joined the event
                cursor.execute("""
                    SELECT id FROM event_volunteers 
                    WHERE event_id = %s AND volunteer_id = %s
                """, (event_id, session['user_id']))

                if cursor.fetchone():
                    return jsonify({'success': False, 'message': 'You have already joined this event.'}), 400

                # Insert volunteer into event_volunteers
                cursor.execute("""
                    INSERT INTO event_volunteers (event_id, volunteer_id, joined_date) 
                    VALUES (%s, %s, %s)
                """, (event_id, session['user_id'], datetime.now()))
                connection.commit()
                return jsonify({'success': True, 'message': 'Successfully joined the event!'})
        cursor.execute("""
            SELECT b.badge_type, DATE_FORMAT(b.awarded_date, '%Y-%m-%d') as awarded_date, e.event_name 
            FROM volunteer_badges b 
            JOIN events e ON b.event_id = e.id 
            WHERE b.volunteer_id = %s 
            ORDER BY b.awarded_date DESC
        """, (session['user_id'],))
        badges = cursor.fetchall()
        return render_template('volunteer.html', 
                               username=session.get('username'), 
                               email=session.get('email'),
                               phone=session.get('mobile'),
                               events=events,
                               badges=badges)

    except Error as e:
        print(f"Database error: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

@app.route('/award_badge', methods=['POST'])
def award_badge():
    if 'user_id' not in session or session.get('role') != 'organiser':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    data = request.get_json()
    volunteer_id = data.get('volunteer_id')
    event_id = data.get('event_id')
    badge_type = data.get('badge_type')

    if not all([volunteer_id, event_id, badge_type]):
        return jsonify({'success': False, 'message': 'Missing required data'}), 400

    connection = create_connection()
    if connection is None:
        return jsonify({'success': False, 'message': 'Database connection failed'}), 500

    try:
        cursor = connection.cursor(dictionary=True)
        
        # First check if badge already exists
        cursor.execute("""
            SELECT id FROM volunteer_badges 
            WHERE volunteer_id = %s AND event_id = %s
        """, (volunteer_id, event_id))
        
        existing_badge = cursor.fetchone()
        
        if existing_badge:
            return jsonify({'success': False, 'message': 'Badge already awarded'}), 400
            
        # Verify the event belongs to the organiser and is completed
        cursor.execute("""
            SELECT id FROM events 
            WHERE id = %s AND organiser_id = %s AND status = 'Completed'
        """, (event_id, session['user_id']))
        
        if not cursor.fetchone():
            return jsonify({'success': False, 'message': 'Unauthorized or event not completed'}), 403

        # Insert new badge
        cursor.execute("""
            INSERT INTO volunteer_badges (volunteer_id, event_id, badge_type, awarded_date) 
            VALUES (%s, %s, %s, NOW())
        """, (volunteer_id, event_id, badge_type))
        
        connection.commit()
        return jsonify({
            'success': True, 
            'message': 'Badge awarded successfully',
            'badge_type': badge_type
        })
        
    except Error as e:
        print(f"Database error: {e}")
        return jsonify({'success': False, 'message': 'Error awarding badge'}), 500
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

@app.route('/get_event_volunteers/<int:event_id>')
def get_event_volunteers(event_id):
    if 'user_id' not in session or session.get('role') != 'organiser':
        return jsonify({'error': 'Unauthorized'}), 401

    connection = create_connection()
    if connection is None:
        return jsonify({'error': 'Database connection failed'}), 500

    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("""
            SELECT u.id, u.username, u.email, u.mobile, u.location, 
                   ev.joined_date, vb.badge_type
            FROM event_volunteers ev
            JOIN users u ON ev.volunteer_id = u.id
            LEFT JOIN volunteer_badges vb ON vb.volunteer_id = u.id 
                AND vb.event_id = ev.event_id
            WHERE ev.event_id = %s
        """, (event_id,))
        volunteers = cursor.fetchall()
        
        return jsonify({'volunteers': volunteers})
    except Error as e:
        print(f"Database error: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

@app.route('/completed_events')
def completed_events():
    if 'user_id' not in session or session.get('role') != 'organiser':
        return redirect(url_for('login'))

    connection = create_connection()
    try:
        cursor = connection.cursor(dictionary=True)
        
        # Calculate totals first
        cursor.execute("""
            SELECT 
                COALESCE(SUM(ev.plastics_collected), 0) as total_plastics,
                COALESCE(SUM(e.products_recycled), 0) as total_products,
                COALESCE(SUM(
                    CASE 
                        WHEN ev.payment_status = 'Paid' 
                        THEN ev.hours_worked * e.salary_per_volunteer 
                        ELSE 0 
                    END
                ), 0) as total_payments
            FROM events e
            LEFT JOIN event_volunteers ev ON e.id = ev.event_id
            WHERE e.organiser_id = %s AND e.status = 'Completed'
        """, (session['user_id'],))
        
        totals = cursor.fetchone()
        
        # Fetch completed events with all details
        cursor.execute("""
            SELECT e.*, 
                   COUNT(DISTINCT ev.id) as volunteer_count
            FROM events e
            LEFT JOIN event_volunteers ev ON e.id = ev.event_id
            WHERE e.organiser_id = %s AND e.status = 'Completed'
            GROUP BY e.id
            ORDER BY e.event_date DESC
        """, (session['user_id'],))
        
        completed_events = cursor.fetchall()
        
        # For each event, fetch its volunteers with plastics collected
        for event in completed_events:
            cursor.execute("""
                SELECT u.id, u.username, ev.hours_worked,
                       ev.plastics_collected,
                       (ev.hours_worked * e.salary_per_volunteer) as payment_due,
                       COALESCE(ev.payment_status, 'Pending') as payment_status
                FROM event_volunteers ev
                JOIN users u ON ev.volunteer_id = u.id
                JOIN events e ON ev.event_id = e.id
                WHERE ev.event_id = %s
            """, (event['id'],))
            event['volunteers'] = cursor.fetchall()
            
        return render_template('completed_events.html', 
                             completed_events=completed_events,
                             total_plastics=float(totals['total_plastics']),
                             total_products=int(totals['total_products']),
                             total_payments=float(totals['total_payments']))

    except Error as e:
        print(f"Database error: {e}")
        return str(e), 500
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.route('/update_volunteer_plastics', methods=['POST'])
def update_volunteer_plastics():
    if 'user_id' not in session or session.get('role') != 'organiser':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    event_id = request.form.get('event_id')
    volunteer_id = request.form.get('volunteer_id')
    plastics = request.form.get('plastics')

    connection = create_connection()
    try:
        cursor = connection.cursor()
        # Update plastics collected for the volunteer
        cursor.execute("""
            UPDATE event_volunteers 
            SET plastics_collected = %s
            WHERE event_id = %s AND volunteer_id = %s
        """, (plastics, event_id, volunteer_id))
        
        # Calculate new total plastics
        cursor.execute("""
            SELECT COALESCE(SUM(plastics_collected), 0) as total_plastics
            FROM event_volunteers
            WHERE event_id = %s
        """, (event_id,))
        
        total_plastics = cursor.fetchone()[0]
        
        connection.commit()
        return jsonify({
            'success': True,
            'total_plastics': float(total_plastics)
        })
    except Error as e:
        return jsonify({'success': False, 'message': str(e)})
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()            
@app.route('/mark-payment/<int:event_id>/<int:volunteer_id>', methods=['POST'])
def mark_payment(event_id, volunteer_id):
    if 'user_id' not in session or session.get('role') != 'organiser':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
        
    connection = create_connection()
    try:
        cursor = connection.cursor()
        cursor.execute("""
            UPDATE event_volunteers 
            SET payment_status = 'Paid'
            WHERE event_id = %s AND volunteer_id = %s
        """, (event_id, volunteer_id))
        connection.commit()
        return jsonify({
            'success': True,
            'message': 'Payment status updated successfully'
        })
        
    except Error as e:
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()            

@app.route('/update_volunteer_hours', methods=['POST'])
def update_volunteer_hours():
    if 'user_id' not in session or session.get('role') != 'organiser':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    event_id = request.form.get('event_id')
    volunteer_id = request.form.get('volunteer_id')
    hours = request.form.get('hours')

    connection = create_connection()
    try:
        cursor = connection.cursor()
        cursor.execute("""
            UPDATE event_volunteers 
            SET hours_worked = %s
            WHERE event_id = %s AND volunteer_id = %s
        """, (hours, event_id, volunteer_id))
        connection.commit()
        return jsonify({'success': True})
    except Error as e:
        return jsonify({'success': False, 'message': str(e)})
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()
@app.route('/update-metrics/<int:event_id>', methods=['POST'])
def update_metrics(event_id):
    if 'user_id' not in session or session.get('role') != 'organiser':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    connection = create_connection()
    try:
        cursor = connection.cursor(dictionary=True)
        
        # Get products_recycled from form
        products_recycled = request.form.get('products_recycled')
        
        if not products_recycled:
            return jsonify({
                'success': False,
                'message': 'Products recycled value is required'
            }), 400
        
        # First verify the event exists and belongs to the organiser
        cursor.execute("""
            SELECT id, products_recycled 
            FROM events 
            WHERE id = %s AND organiser_id = %s
        """, (event_id, session['user_id']))
        
        event = cursor.fetchone()
        if not event:
            return jsonify({
                'success': False,
                'message': 'Event not found or unauthorized'
            }), 404
            
        # Update the event metrics
        cursor.execute("""
            UPDATE events 
            SET products_recycled = %s
            WHERE id = %s AND organiser_id = %s
        """, (products_recycled, event_id, session['user_id']))
        
        # Get the updated value to confirm
        cursor.execute("""
            SELECT products_recycled
            FROM events
            WHERE id = %s AND organiser_id = %s
        """, (event_id, session['user_id']))
        
        updated_value = cursor.fetchone()
        
        connection.commit()
        
        return jsonify({
            'success': True, 
            'message': 'Metrics updated successfully',
            'totals': {
                'total_products': updated_value['products_recycled'] if updated_value else products_recycled
            }
        })
        
    except Error as e:
        connection.rollback()
        print(f"Error updating metrics: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500
        
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()
            
@app.route('/volunteer/history')
def volunteer_history():
    if 'user_id' not in session or session.get('role') != 'volunteer':
        return redirect(url_for('login'))

    connection = create_connection()
    if connection is None:
        flash('Database connection failed.', 'error')
        return redirect(url_for('login'))

    try:
        cursor = connection.cursor(dictionary=True)
        
        # Fetch completed events for the volunteer
        cursor.execute("""
            SELECT 
                e.id,
                e.event_name,
                e.event_date,
                e.event_time,
                e.photo_path,
                e.salary_per_volunteer,
                ev.hours_worked,
                ev.payment_status,
                u.username as organiser_name,
                u.email as organiser_email,
                u.mobile as organiser_mobile,
                (ev.hours_worked * e.salary_per_volunteer) as total_payment,
                e.plastics_collected,
                e.products_recycled
            FROM events e
            JOIN event_volunteers ev ON e.id = ev.event_id
            JOIN users u ON e.organiser_id = u.id
            WHERE ev.volunteer_id = %s 
            AND e.status = 'Completed'
            ORDER BY e.event_date DESC
        """, (session['user_id'],))
        
        completed_events = cursor.fetchall()
        
        return render_template('volunteer_history.html', 
                             completed_events=completed_events,
                             username=session.get('username'))

    except Error as e:
        print(f"Database error: {e}")
        return str(e), 500
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

# Add this new route to handle feedback submission
@app.route('/submit-feedback', methods=['POST'])
def submit_feedback():
    if 'user_id' not in session or session.get('role') != 'volunteer':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    event_id = request.form.get('eventId')
    rating = request.form.get('rating')
    feedback_text = request.form.get('feedback')

    if not all([event_id, rating, feedback_text]):
        return jsonify({'success': False, 'message': 'Missing required fields'}), 400

    connection = create_connection()
    try:
        cursor = connection.cursor()
        
        # Insert feedback into database
        cursor.execute("""
            INSERT INTO event_feedback 
            (event_id, volunteer_id, rating, feedback_text, submission_date) 
            VALUES (%s, %s, %s, %s, NOW())
        """, (event_id, session['user_id'], rating, feedback_text))
        
        connection.commit()
        return jsonify({'success': True, 'message': 'Feedback submitted successfully'})
    except Error as e:
        print(f"Database error: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()                        

@app.route('/organiser/feedbacks')
def organiser_feedbacks():
    if 'user_id' not in session or session.get('role') != 'organiser':
        return redirect(url_for('login'))
    
    connection = create_connection()
    if connection is None:
        flash('Database connection failed.', 'error')
        return redirect(url_for('login'))
    
    try:
        cursor = connection.cursor(dictionary=True)
        
        # Fetch completed events for the organiser
        cursor.execute("""
            SELECT 
                e.id,
                e.event_name,
                e.event_date,
                e.status,
                GROUP_CONCAT(u.username) as volunteer_names
            FROM events e
            LEFT JOIN event_volunteers ev ON e.id = ev.event_id
            LEFT JOIN users u ON ev.volunteer_id = u.id
            WHERE e.organiser_id = %s AND e.status = 'Completed'
            GROUP BY e.id
            ORDER BY e.event_date DESC
        """, (session['user_id'],))
        
        events = cursor.fetchall()
        
        # Fetch feedbacks
        cursor.execute("""
            SELECT 
                e.event_name,
                u.username as volunteer_name,
                f.rating,
                f.feedback_text,
                f.submission_date,
                e.event_date
            FROM event_feedback f
            JOIN events e ON f.event_id = e.id
            JOIN users u ON f.volunteer_id = u.id
            WHERE e.organiser_id = %s
            ORDER BY f.submission_date DESC
        """, (session['user_id'],))
        
        feedbacks = cursor.fetchall()
        
        total_rating = sum(feedback['rating'] for feedback in feedbacks) if feedbacks else 0
        avg_rating = round(total_rating / len(feedbacks), 1) if feedbacks else 0
        
        feedback_stats = {
            'total_feedbacks': len(feedbacks),
            'average_rating': avg_rating
        }
        
        return render_template('organiser_feedbacks.html',
                            events=events,
                            feedbacks=feedbacks,
                            feedback_stats=feedback_stats,
                            username=session.get('username'))
    
    except Error as e:
        print(f"Database error: {e}")
        return str(e), 500
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()
'''@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))'''

@app.route('/guides')
def guides():
    return render_template('guides.html')

@app.route('/donation')
def donation():
    connection = create_connection()
    try:
        cursor = connection.cursor(dictionary=True)
        
        # Modified query to correctly calculate impact stats
        cursor.execute("""
            SELECT 
                COUNT(DISTINCT e.id) as total_events,
                COUNT(DISTINCT ev.volunteer_id) as total_volunteers,
                COALESCE(SUM(ev.plastics_collected), 0) as total_plastics,
                (
                    SELECT COALESCE(SUM(products_recycled), 0)
                    FROM events 
                    WHERE status = 'Completed'
                ) as total_products
            FROM events e
            LEFT JOIN event_volunteers ev ON e.id = ev.event_id
            WHERE e.status = 'Completed'
        """)
        impact_stats = cursor.fetchone()
    
        return render_template('donation.html', impact_stats=impact_stats)
    except Error as e:
        print(f"Database error: {e}")
        return str(e), 500
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.route('/process_donation', methods=['POST'])
def process_donation():
    if not request.form:
        return jsonify({'success': False, 'message': 'No form data received'}), 400
    
    # Get donor information
    donor_info = {
        'name': request.form.get('name'),
        'email': request.form.get('email'),
        'phone': request.form.get('phone'),
        'amount': request.form.get('amount')
    }
    
    # Validate required fields
    if not all(donor_info.values()):
        flash('All fields are required.', 'error')
        return redirect(url_for('donation'))
    
    # Store donor information in session for next step
    session['donor_info'] = donor_info
    
    return redirect(url_for('select_organiser'))

@app.route('/select_organiser')
def select_organiser():
    if 'donor_info' not in session:
        flash('Please fill out the donation form first.', 'error')
        return redirect(url_for('donation'))
    
    connection = create_connection()
    if connection is None:
        flash('Database connection failed.', 'error')
        return redirect(url_for('donation'))
    
    try:
        cursor = connection.cursor(dictionary=True)
        
        # Fetch organizers with their cleanup statistics
        cursor.execute("""
            SELECT 
                u.id,
                u.username,
                u.email,
                u.mobile,
                u.location,
                COUNT(DISTINCT e.id) as total_events,
                COALESCE(SUM(e.plastics_collected), 0) as total_plastics_collected
            FROM users u
            LEFT JOIN events e ON u.id = e.organiser_id AND e.status = 'Completed'
            WHERE u.role = 'organiser'
            GROUP BY u.id, u.username, u.email, u.mobile, u.location
            ORDER BY total_events DESC
        """)
        
        organisers = cursor.fetchall()
        
        return render_template('select_organiser.html',
                             donor_info=session.get('donor_info', {}),
                             organisers=organisers)
    
    except Error as e:
        print(f"Database error: {e}")
        flash('An error occurred while fetching organisers.', 'error')
        return redirect(url_for('donation'))
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.route('/finalize_donation', methods=['POST'])
def finalize_donation():
    if 'donor_info' not in session:
        flash('Donation information not found. Please start over.', 'error')
        return redirect(url_for('donation'))
    
    organiser_id = request.form.get('organiser_id')
    if not organiser_id:
        flash('No organiser selected.', 'error')
        return redirect(url_for('select_organiser'))
    
    connection = create_connection()
    try:
        cursor = connection.cursor()
        
        # Insert donation record
        cursor.execute("""
            INSERT INTO donations (
                donor_name, donor_email, donor_phone,
                amount, organiser_id, donation_date, status
            ) VALUES (%s, %s, %s, %s, %s, NOW(), 'Pending')
        """, (
            session['donor_info']['name'],
            session['donor_info']['email'],
            session['donor_info']['phone'],
            session['donor_info']['amount'],
            organiser_id
        ))
        
        connection.commit()
        donation_id = cursor.lastrowid
        
        # Clear donation info from session
        session.pop('donor_info', None)
        
        flash('Thank you for your donation! Your contribution has been recorded.', 'success')
        return redirect(url_for('donation_confirmation', donation_id=donation_id))
        
    except Error as e:
        print(f"Database error: {e}")
        flash('An error occurred while processing your donation. Please try again.', 'error')
        return redirect(url_for('select_organiser'))
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.route('/donation_confirmation/<int:donation_id>')
def donation_confirmation(donation_id):
    connection = create_connection()
    try:
        cursor = connection.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT d.*, u.username as organiser_name
            FROM donations d
            JOIN users u ON d.organiser_id = u.id
            WHERE d.id = %s
        """, (donation_id,))
        
        donation = cursor.fetchone()
        
        if not donation:
            flash('Donation record not found.', 'error')
            return redirect(url_for('donation'))
            
        return render_template('donation_confirmation.html', donation=donation)
        
    except Error as e:
        print(f"Database error: {e}")
        flash('An error occurred while fetching donation details.', 'error')
        return redirect(url_for('donation'))
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()
def get_address_from_coordinates(lat, lng):
    """Convert coordinates to human readable address using Nominatim"""
    try:
        # Using Nominatim OpenStreetMap service for reverse geocoding
        url = f"https://nominatim.openstreetmap.org/reverse?lat={lat}&lon={lng}&format=json"
        
        # Add User-Agent as it's required by Nominatim's Terms of Service
        headers = {
            'User-Agent': 'EcoPlast/1.0'
        }
        
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            if 'address' in data:
                addr = data['address']
                # Constructing a formatted address from components
                address_parts = []
                
                # Add road/street if available
                if 'road' in addr:
                    address_parts.append(addr['road'])
                
                # Add suburb/area if available
                if 'suburb' in addr:
                    address_parts.append(addr['suburb'])
                
                # Add city
                if 'city' in addr:
                    address_parts.append(addr['city'])
                elif 'town' in addr:
                    address_parts.append(addr['town'])
                
                # Add state
                if 'state' in addr:
                    address_parts.append(addr['state'])
                
                # Add postal code
                if 'postcode' in addr:
                    address_parts.append(f"PIN: {addr['postcode']}")
                
                return '\n'.join(address_parts)
            
        return "Address not found"
    except Exception as e:
        print(f"Error in geocoding: {e}")
        return "Error fetching address"
@app.route('/cart')
def cart():
    if 'user_id' not in session:
        flash('Please login to access this page.', 'error')
        return redirect(url_for('login'))
    return render_template('cart.html')

@app.route('/history')
def history():
    if 'user_id' not in session:
        flash('Please login to access this page.', 'error')
        return redirect(url_for('login'))
    return render_template('history.html')
@app.route('/payment')
def payment():
    return render_template('payment.html')
@app.route('/success')
def success():
    return render_template('success.html')
@app.route('/buyer_details')
def get_buyer_details():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authorized'}), 401
    
    try:
        connection = create_connection()
        cursor = connection.cursor(dictionary=True)
        
        # Updated query to use purchase_history table
        query = """
        SELECT 
            u.username,
            u.email,
            u.mobile,
            ph.product_name,
            ph.price,
            ph.purchase_date,
            p.organiser_id,
            ph.status
        FROM purchase_history ph
        JOIN users u ON ph.user_id = u.id
        JOIN products p ON ph.product_id = p.id
        WHERE p.organiser_id = %s AND ph.status = 'Completed'
        ORDER BY ph.purchase_date DESC
        """
        
        cursor.execute(query, (session['user_id'],))
        purchases = cursor.fetchall()
        
        # Process the purchases into buyer details
        buyers_dict = {}
        for purchase in purchases:
            buyer_email = purchase['email']
            if buyer_email not in buyers_dict:
                buyers_dict[buyer_email] = {
                    'username': purchase['username'],
                    'email': purchase['email'],
                    'mobile': purchase['mobile'],
                    'total_amount': 0,
                    'total_products': 0,
                    'products': set(),
                    'last_purchase_date': purchase['purchase_date'].strftime('%Y-%m-%d %H:%M:%S')
                }
            
            buyers_dict[buyer_email]['total_amount'] += float(purchase['price'])
            buyers_dict[buyer_email]['total_products'] += 1
            buyers_dict[buyer_email]['products'].add(purchase['product_name'])
            
            # Update last purchase date if this purchase is more recent
            purchase_date = purchase['purchase_date'].strftime('%Y-%m-%d %H:%M:%S')
            if purchase_date > buyers_dict[buyer_email]['last_purchase_date']:
                buyers_dict[buyer_email]['last_purchase_date'] = purchase_date
        
        # Convert sets to lists for JSON serialization
        buyers_list = []
        for buyer in buyers_dict.values():
            buyer['products'] = list(buyer['products'])
            buyer['total_amount'] = round(buyer['total_amount'], 2)
            buyers_list.append(buyer)
        
        return jsonify({
            'success': True,
            'buyers': buyers_list
        })
    
    except Exception as e:
        print(f"Error fetching buyer details: {e}")
        return jsonify({
            'success': False,
            'message': 'Error fetching buyer details'
        }), 500
    
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

# In the sales route, ensure the discount is applied based on the badge
@app.route('/sales')
def sales():
    if 'user_id' not in session:
        flash('Please login to access this page.', 'error')
        return redirect(url_for('login'))

    connection = create_connection()
    try:
        cursor = connection.cursor(dictionary=True)

        # Fetch all approved products with organiser name
        cursor.execute("""
            SELECT p.*, u.username as organiser_name 
            FROM products p
            JOIN users u ON p.organiser_id = u.id
            WHERE p.status = 'Approved'
            ORDER BY p.id DESC
        """)
        products = cursor.fetchall()

        # Fetch user details
        user_role = session.get('role', '')
        user_id = session.get('user_id', None)

        # Discount mapping based on badges
        discount_map = {"bronze": 5, "gold": 10, "platinum": 15, "diamond": 20}
        discount_percentage = 0  # Default: No discount

        # Check if the user is a volunteer with a badge
        if user_role == 'volunteer' and user_id:
            cursor.execute("""
                SELECT badge_type FROM volunteer_badges 
                WHERE volunteer_id = %s 
                ORDER BY FIELD(badge_type, 'bronze', 'gold', 'platinum', 'diamond') DESC 
                LIMIT 1
            """, (user_id,))
            badge_result = cursor.fetchone()

            if badge_result:
                highest_badge = badge_result['badge_type']
                discount_percentage = discount_map.get(highest_badge, 0)  # Get discount based on badge

        # Process each product (format quantity, apply discount, set image URL)
        for product in products:
            original_price = float(product['price'])
            product['original_price'] = original_price

            # Apply discount if applicable
            if discount_percentage > 0:
                discounted_price = original_price * (1 - discount_percentage / 100)
                product['discounted_price'] = round(discounted_price, 2)
            else:
                product['discounted_price'] = original_price

            # Format quantity display
            if product['quantity'] is None:
                product['formatted_quantity'] = "Not Available"
            elif product['category'] == 'wholesale':
                product['formatted_quantity'] = f"{float(product['quantity']):.2f} kg"
            else:
                product['formatted_quantity'] = f"{int(product['quantity'])} items"

            # Set product image URL
            if product['image_path']:
                product['image_url'] = url_for('static', filename=f'uploads/{product["image_path"]}')
            else:
                product['image_url'] = url_for('static', filename='default-product.jpg')

        # Get user location details and format coordinates into an address
        location = session.get('location', '')
        try:
            if ',' in location:
                lat, lng = map(float, location.split(','))
                formatted_address = get_address_from_coordinates(lat, lng)
            else:
                formatted_address = location
        except:
            formatted_address = location

        # Prepare user data for display
        user_data = {
            'username': session.get('username'),
            'email': session.get('email'),
            'mobile': session.get('mobile'),
            'location': formatted_address,
            'role': user_role
        }

        return render_template('sales.html', products=products, user=user_data, discount_percentage=discount_percentage)

    except Error as e:
        print(f"Database error: {e}")
        flash('Error fetching products.', 'error')
        return redirect(url_for('home'))
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()


@app.route('/upload_product', methods=['POST'])
def upload_product():
    if 'user_id' not in session or session.get('role') != 'organiser':
        return redirect(url_for('login'))
    
    connection = None
    cursor = None
    
    try:
        # Get basic form data with better error handling
        product_name = request.form.get('product-name', '').strip()
        product_type = request.form.get('product-type', '').strip().lower()  # Normalize case
        price = request.form.get('price', '')
        quantity = request.form.get('quantity', '')
        description = request.form.get('description', '').strip()

        # Log the incoming data for debugging
        app.logger.info(f"Received product data - Type: {product_type}, Quantity: {quantity}, Price: {price}")

        # Validate required fields with specific messages
        if not product_name:
            return jsonify({'success': False, 'message': 'Product name is required'}), 400
        if not product_type:
            return jsonify({'success': False, 'message': 'Product type is required'}), 400
        if not price:
            return jsonify({'success': False, 'message': 'Price is required'}), 400
        if not quantity:
            return jsonify({'success': False, 'message': 'Quantity is required'}), 400
        if not description:
            return jsonify({'success': False, 'message': 'Description is required'}), 400

        # Create database connection
        connection = create_connection()
        if not connection:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
        
        cursor = connection.cursor(dictionary=True)
        
        # Set transaction isolation level to SERIALIZABLE for maximum consistency
        cursor.execute("SET SESSION TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        
        # Start transaction
        cursor.execute("START TRANSACTION")
        
        # Lock the products table for this check to prevent race conditions
        cursor.execute("SELECT id FROM products WHERE name = %s AND organiser_id = %s AND status != 'Deleted' FOR UPDATE", 
                      (product_name, session['user_id']))
        
        existing_product = cursor.fetchone()
        if existing_product:
            connection.rollback()
            return jsonify({
                'success': False,
                'message': 'A product with this name already exists in your inventory'
            }), 400

        # Handle price conversion
        try:
            price = float(price)
            if price <= 0:
                return jsonify({
                    'success': False,
                    'message': 'Price must be greater than 0'
                }), 400
        except (ValueError, TypeError) as e:
            app.logger.error(f"Price conversion error: {str(e)}")
            return jsonify({
                'success': False,
                'message': 'Invalid price format. Please enter a valid number.'
            }), 400

        # Handle quantity based on product type
        try:
            if product_type == 'wholesale':
                try:
                    quantity = float(quantity)
                    units = 'kg'
                except (ValueError, TypeError) as e:
                    app.logger.error(f"Wholesale quantity conversion error: {str(e)}")
                    return jsonify({
                        'success': False,
                        'message': 'For wholesale products, quantity must be a valid number in kilograms'
                    }), 400
            elif product_type == 'recycled':
                try:
                    quantity = int(float(quantity))
                    units = 'units'
                except (ValueError, TypeError) as e:
                    app.logger.error(f"Recycled quantity conversion error: {str(e)}")
                    return jsonify({
                        'success': False,
                        'message': 'For recycled products, quantity must be a whole number'
                    }), 400
            else:
                return jsonify({
                    'success': False,
                    'message': f'Invalid product type: {product_type}. Must be wholesale or recycled.'
                }), 400

            if quantity <= 0:
                return jsonify({
                    'success': False,
                    'message': 'Quantity must be greater than 0'
                }), 400

        except Exception as e:
            app.logger.error(f"Quantity processing error: {str(e)}")
            return jsonify({
                'success': False,
                'message': f'Error processing quantity: {str(e)}'
            }), 400
            
        # Handle image upload
        if 'product-image' not in request.files:
            return jsonify({
                'success': False,
                'message': 'Please upload a product image'
            }), 400
            
        file = request.files['product-image']
        if file.filename == '':
            return jsonify({
                'success': False,
                'message': 'No image selected'
            }), 400
            
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        else:
            return jsonify({
                'success': False,
                'message': 'Invalid image format'
            }), 400

        # Double-check for duplicates one more time before insert
        cursor.execute("""
            SELECT id FROM products 
            WHERE name = %s AND organiser_id = %s AND status != 'Deleted'
            FOR UPDATE
        """, (product_name, session['user_id']))
        
        if cursor.fetchone():
            connection.rollback()
            return jsonify({
                'success': False,
                'message': 'A product with this name already exists in your inventory'
            }), 400

        # Insert the product with a unique constraint
        sql_query = """
            INSERT INTO products (
                name, price, description, image_path,
                organiser_id, status, category,
                units, quantity
            )
            VALUES (%s, %s, %s, %s, %s, 'Pending', %s, %s, %s)
        """
        values = (
            product_name,
            price,
            description,
            filename,
            session['user_id'],
            product_type,
            units,
            quantity
        )
        
        cursor.execute(sql_query, values)
        new_product_id = cursor.lastrowid
        
        # Commit the transaction
        connection.commit()
        
        return jsonify({
            'success': True,
            'message': 'Product uploaded successfully',
            'product_id': new_product_id
        })
            
    except Exception as e:
        # Log the specific error
        app.logger.error(f"Error in upload_product: {str(e)}", exc_info=True)
        
        # Rollback transaction if there was a database error
        if connection:
            try:
                connection.rollback()
            except:
                pass
            
        return jsonify({
            'success': False,
            'message': f'Error uploading product: {str(e)}'
        }), 500
            
    finally:
        # Ensure database connections are always closed
        if cursor:
            try:
                cursor.close()
            except:
                pass
        if connection and connection.is_connected():
            try:
                connection.close()
            except:
                pass           

@app.route('/products')
def products():
    connection = create_connection()
    try:
        cursor = connection.cursor(dictionary=True)
        # Fetch products with quantity and other details
        cursor.execute("""
            SELECT p.id, p.name, p.description, p.image_url, p.price, 
                   p.quantity, p.category 
            FROM products p
            WHERE p.status = 'Approved'
        """)
        products = cursor.fetchall()
        return render_template('sales.html', products=products)
    except Error as e:
        print(f"Database error: {e}")
        return "Error fetching products", 500
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()
@app.route('/process_purchase', methods=['POST'])
def process_purchase():
    print("Starting purchase process...")  # Debug log
    
    if 'user_id' not in session:
        print("User not logged in")  # Debug log
        return jsonify({'error': 'Not logged in'}), 401
        
    connection = None
    cursor = None
    
    try:
        # Log the received data
        data = request.json
        print(f"Received purchase data: {data}")  # Debug log
        
        if not data:
            print("No data received in request")  # Debug log
            return jsonify({'error': 'No data received'}), 400
            
        product_id = data.get('product_id')
        if not product_id:
            print("No product_id in request data")  # Debug log
            return jsonify({'error': 'Product ID is required'}), 400
            
        # Create database connection
        connection = create_connection()
        print("Database connection created")  # Debug log
        
        cursor = connection.cursor(dictionary=True)
        print("Cursor created")  # Debug log
        
        # Start transaction
        connection.start_transaction()
        print("Transaction started")  # Debug log
        
        # Check product exists and get details
        cursor.execute("""
            SELECT p.*, u.role as user_role
            FROM products p
            LEFT JOIN users u ON u.id = %s
            WHERE p.id = %s
        """, (session['user_id'], product_id))
        
        product_info = cursor.fetchone()
        print(f"Product info fetched: {product_info}")  # Debug log
        
        if not product_info:
            print(f"Product not found for ID: {product_id}")  # Debug log
            return jsonify({'error': 'Product not found'}), 404
            
        # Get purchase quantity
        purchase_quantity = int(data.get('quantity', 1))
        print(f"Purchase quantity: {purchase_quantity}")  # Debug log
        
        # Calculate price
        original_price = float(product_info['price'])
        final_price = original_price
        
        print(f"Original price: {original_price}")  # Debug log
        
        # Check for volunteer discount
        if product_info['user_role'] == 'volunteer':
            print("User is a volunteer, checking for badges")  # Debug log
            cursor.execute("""
                SELECT badge_type 
                FROM volunteer_badges 
                WHERE volunteer_id = %s 
                ORDER BY FIELD(badge_type, 'bronze', 'gold', 'platinum', 'diamond') DESC 
                LIMIT 1
            """, (session['user_id'],))
            
            badge = cursor.fetchone()
            if badge:
                discount_map = {
                    "bronze": 5,
                    "gold": 10,
                    "platinum": 15,
                    "diamond": 20
                }
                discount = discount_map.get(badge['badge_type'].lower(), 0)
                final_price = original_price * (1 - discount/100)
                print(f"Applied volunteer discount: {discount}%. Final price: {final_price}")  # Debug log
        
        # Update product quantity
        new_quantity = product_info['quantity'] - purchase_quantity
        
        print(f"Updating product quantity from {product_info['quantity']} to {new_quantity}")  # Debug log
        
        update_query = """
            UPDATE products 
            SET quantity = %s 
            WHERE id = %s
        """
        cursor.execute(update_query, (new_quantity, product_id))
        print("Product quantity updated")  # Debug log
        
        # Insert purchase record
        insert_query = """
            INSERT INTO purchase_history (
                user_id, 
                product_id, 
                product_name,
                quantity,
                price,
                discounted_price,
                total_amount,
                purchase_date,
                status
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, NOW(), 'Completed')
        """
        
        insert_values = (
            session['user_id'],
            product_id,
            product_info['name'],
            purchase_quantity,
            original_price,
            final_price if final_price != original_price else None,
            final_price * purchase_quantity
        )
        
        print(f"Inserting purchase record with values: {insert_values}")  # Debug log
        
        cursor.execute(insert_query, insert_values)
        print("Purchase record inserted")  # Debug log
        
        # Remove from cart if needed
        if data.get('from_cart'):
            print("Removing item from cart")  # Debug log
            cursor.execute("""
                DELETE FROM cart 
                WHERE user_id = %s AND product_id = %s
            """, (session['user_id'], product_id))
        
        # Commit transaction
        connection.commit()
        print("Transaction committed successfully")  # Debug log
        
        return jsonify({
            'success': True,
            'message': 'Purchase processed successfully',
            'new_quantity': new_quantity,
            'transaction_id': cursor.lastrowid
        })
        
    except Error as e:
        print(f"Database error occurred: {str(e)}")  # Debug log
        if connection:
            connection.rollback()
            print("Transaction rolled back")  # Debug log
        return jsonify({'error': f'Database error: {str(e)}'}), 500
        
    except Exception as e:
        print(f"General error occurred: {str(e)}")  # Debug log
        if connection:
            connection.rollback()
            print("Transaction rolled back")  # Debug log
        return jsonify({'error': f'Error processing purchase: {str(e)}'}), 500
        
    finally:
        if cursor:
            cursor.close()
            print("Cursor closed")  # Debug log
        if connection and connection.is_connected():
            connection.close()
            print("Connection closed")  # Debug log
# Frontend JavaScript updates
def update_quantity_display():
    script = """
    function formatQuantity(quantity, category) {
        if (quantity <= 0) return 'Out of Stock';
        return category === 'wholesale' ? 
            `${quantity.toFixed(2)} kg` : 
            `${Math.floor(quantity)} items`;
    }
    
    function updateProductStock(productId, newQuantity, category) {
        const productCard = document.querySelector(`[data-product-id="${productId}"]`);
        if (!productCard) return;
        
        const quantityTag = productCard.querySelector('.quantity-tag');
        const purchaseBtn = productCard.querySelector('.purchase-btn');
        const cartBtn = productCard.querySelector('.cart-btn');
        
        if (!quantityTag || !purchaseBtn || !cartBtn) return;
        
        if (newQuantity <= 0) {
            quantityTag.innerHTML = `
                <i class="fas fa-ban"></i>
                Out of Stock
            `;
            quantityTag.classList.add('out-of-stock');
            purchaseBtn.disabled = true;
            cartBtn.disabled = true;
            purchaseBtn.classList.add('disabled-button');
            cartBtn.classList.add('disabled-button');
            purchaseBtn.innerHTML = '<i class="fas fa-shopping-bag"></i> Out of Stock';
        } else {
            const formattedQuantity = formatQuantity(newQuantity, category);
            quantityTag.innerHTML = `
                <i class="fas fa-cubes"></i>
                ${formattedQuantity}
            `;
            quantityTag.classList.remove('out-of-stock');
            purchaseBtn.disabled = false;
            cartBtn.disabled = false;
            purchaseBtn.classList.remove('disabled-button');
            cartBtn.classList.remove('disabled-button');
            purchaseBtn.innerHTML = '<i class="fas fa-shopping-bag"></i> Buy Now';
        }
    }
    
    function processPurchase() {
        const formData = {
            product_id: window.currentProductId,
            product_name: document.getElementById('modalProductName').textContent,
            price: parseFloat(document.getElementById('modalProductPrice').textContent),
            location: document.getElementById('buyerLocation').value,
            quantity: 1,
            from_cart: false
        };
    
        const confirmBtn = document.querySelector('.confirm-btn');
        const originalContent = confirmBtn.innerHTML;
        confirmBtn.innerHTML = '<div class="loading-spinner"></div> Processing...';
        confirmBtn.disabled = true;
    
        fetch('/process_purchase', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(formData)
        })
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                showNotification(data.error, 'error');
            } else {
                showNotification('Purchase completed successfully!', 'success');
                
                // Update the product stock display
                const productCard = document.querySelector(`[data-product-id="${formData.product_id}"]`);
                const category = productCard ? productCard.dataset.category : '';
                updateProductStock(formData.product_id, data.new_quantity, category);
                
                closePurchaseModal();
                
                if (document.getElementById('profileSection').style.display === 'block') {
                    loadPurchaseHistory();
                }
            }
        })
        .catch(error => {
            console.error('Error:', error);
            showNotification('Error processing purchase', 'error');
        })
        .finally(() => {
            confirmBtn.innerHTML = originalContent;
            confirmBtn.disabled = false;
        });
    }
    """
    return script            
           
@app.route('/get_user_profile')
def get_user_profile():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    location = session.get('location', '')
    try:
        if ',' in location:
            lat, lng = map(float, location.split(','))
            formatted_address = get_human_readable_location(location)
        else:
            formatted_address = location
    except:
        formatted_address = location
    
    user_data = {
        'username': session.get('username'),
        'email': session.get('email'),
        'mobile': session.get('mobile'),
        'location': formatted_address,
        'role': session.get('role')
    }
    return jsonify(user_data)

def get_human_readable_location(location):
    if ',' in location:
        try:
            lat, lon = map(float, location.split(','))
            response = requests.get(NOMINATIM_URL, 
                params={'lat': lat, 'lon': lon, 'format': 'json'}, 
                headers={'User-Agent': 'GeoLocator'}
            )
            response.raise_for_status()
            data = response.json()
            return data.get('display_name', location)
        except Exception as e:
            print(f"Location conversion error: {e}")
    return location

@app.route('/get_profile')
def get_profile():
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'User not logged in'}), 401
    
    connection = create_connection()
    if connection is None:
        return jsonify({'success': False, 'error': 'Database connection failed'}), 500
    
    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("""
            SELECT id, username, email, mobile, location 
            FROM users 
            WHERE id = %s
        """, (session['user_id'],))
        
        user_data = cursor.fetchone()
        
        if not user_data:
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        # Convert location to human-readable format
        location = user_data['location']
        human_readable_location = get_human_readable_location(location)
        
        profile_data = {
            'full_name': user_data['username'],
            'email': user_data['email'],
            'phone': user_data['mobile'],
            'address': human_readable_location
        }
        
        return jsonify({'success': True, 'data': profile_data})
    
    except Exception as e:
        print(f"Error fetching profile: {str(e)}")
        return jsonify({'success': False, 'error': f'Database error: {str(e)}'}), 500
    
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.route('/add_to_cart', methods=['POST'])
def add_to_cart():
    try:
        if not request.is_json:
            return jsonify({'success': False, 'error': 'Request must be JSON'}), 400

        data = request.get_json()
        product_id = data.get('product_id')
        user_id = session.get('user_id')

        if not product_id:
            return jsonify({'success': False, 'error': 'Product ID is required'}), 400
        if not user_id:
            return jsonify({'success': False, 'error': 'Please login to add items to cart'}), 401

        connection = create_connection()
        if not connection:
            return jsonify({'success': False, 'error': 'Database connection failed'}), 500

        cursor = connection.cursor(dictionary=True)

        try:
            # First, get the user's role to check if they're a volunteer
            cursor.execute("SELECT role FROM users WHERE id = %s", (user_id,))
            user = cursor.fetchone()
            is_volunteer = user and user['role'] == 'volunteer'

            # Check if product exists and get its details
            cursor.execute("""
                SELECT id, quantity, name, price, discounted_price 
                FROM products 
                WHERE id = %s
            """, (product_id,))
            product = cursor.fetchone()

            if not product:
                return jsonify({'success': False, 'error': 'Product not found'}), 404

            if product['quantity'] is None or product['quantity'] <= 0:
                return jsonify({'success': False, 'error': 'Product is out of stock'}), 400

            # Set the appropriate price based on user role
            original_price = product['price']
            applied_discount_price = product['discounted_price'] if is_volunteer else None

            # Check if product is already in cart
            cursor.execute("""
                SELECT id, quantity 
                FROM cart 
                WHERE user_id = %s AND product_id = %s
            """, (user_id, product_id))
            cart_item = cursor.fetchone()

            if cart_item:
                # Update existing cart item
                new_quantity = cart_item['quantity'] + 1
                if new_quantity > product['quantity']:
                    return jsonify({'success': False, 'error': 'Requested quantity exceeds available stock'}), 400

                cursor.execute("""
                    UPDATE cart 
                    SET quantity = %s,
                        price = %s,
                        discounted_price = %s
                    WHERE id = %s
                """, (new_quantity, original_price, applied_discount_price, cart_item['id']))
            else:
                # Add new cart item with product name, price, and discounted price
                cursor.execute("""
                    INSERT INTO cart (
                        user_id, 
                        product_id, 
                        quantity, 
                        product_name, 
                        price, 
                        discounted_price
                    ) 
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (
                    user_id, 
                    product_id, 
                    1, 
                    product['name'], 
                    original_price, 
                    applied_discount_price
                ))

            connection.commit()

            # Get updated cart count
            cursor.execute("""
                SELECT SUM(quantity) as cart_count 
                FROM cart 
                WHERE user_id = %s
            """, (user_id,))
            cart_count = cursor.fetchone()['cart_count'] or 0

            return jsonify({
                'success': True,
                'message': 'Product added to cart successfully',
                'cart_count': cart_count
            })

        except Error as e:
            connection.rollback()
            logging.error(f"Database error: {str(e)}")
            return jsonify({'success': False, 'error': 'Database error occurred'}), 500

        finally:
            cursor.close()
            connection.close()

    except Exception as e:
        logging.error(f"Server error: {str(e)}")
        return jsonify({'success': False, 'error': 'An error occurred while processing your request'}), 500



    


# Add this route to get cart count
@app.route('/get_cart_count', methods=['GET'])
def get_cart_count():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'cart_count': 0})

    try:
        connection = create_connection()
        cursor = connection.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT SUM(quantity) as cart_count 
            FROM cart 
            WHERE user_id = %s
        """, (user_id,))
        
        result = cursor.fetchone()
        cart_count = result['cart_count'] if result['cart_count'] else 0
        
        return jsonify({'cart_count': cart_count})
        
    except Error as e:
        logging.error(f"Database error: {str(e)}")
        return jsonify({'error': 'Database error occurred'}), 500
        
    finally:
        if 'connection' in locals() and connection.is_connected():
            cursor.close()
            connection.close()

@app.route('/get_cart', methods=['GET'])
def get_cart():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
        
    connection = create_connection()
    try:
        cursor = connection.cursor(dictionary=True)
        
        # First check if user is a volunteer and get their highest badge
        cursor.execute("""
            SELECT role FROM users WHERE id = %s
        """, (session['user_id'],))
        user = cursor.fetchone()
        
        discount_percentage = 0
        if user and user['role'] == 'volunteer':
            # Get the highest badge for the volunteer
            cursor.execute("""
                SELECT badge_type 
                FROM volunteer_badges 
                WHERE volunteer_id = %s 
                ORDER BY FIELD(badge_type, 'bronze', 'gold', 'platinum', 'diamond') DESC 
                LIMIT 1
            """, (session['user_id'],))
            badge = cursor.fetchone()
            
            if badge:
                badge_discounts = {
                    'bronze': 5,
                    'gold': 10,
                    'platinum': 15,
                    'diamond': 20
                }
                discount_percentage = badge_discounts.get(badge['badge_type'].lower(), 0)
        
        # Get cart items with product details
        cursor.execute("""
            SELECT 
                c.*,
                p.image_path,
                p.price as original_price
            FROM cart c
            JOIN products p ON c.product_id = p.id
            WHERE c.user_id = %s
        """, (session['user_id'],))
        
        cart_items = cursor.fetchall()
        
        # Process each cart item
        for item in cart_items:
            # Set image URL
            if item['image_path']:
                item['image_url'] = url_for('static', filename=f'uploads/{item["image_path"]}')
            else:
                item['image_url'] = url_for('static', filename='default-product.jpg')
            
            # Calculate discounted price if applicable
            original_price = float(item['original_price'])
            item['price'] = original_price
            
            if discount_percentage > 0:
                item['discounted_price'] = round(original_price * (1 - discount_percentage/100), 2)
            else:
                item['discounted_price'] = None
                
        return jsonify(cart_items)
        
    except Error as e:
        print(f"Database error in get_cart: {str(e)}")
        return jsonify({'error': 'Database error'}), 500
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()




@app.route('/remove_from_cart', methods=['POST'])
def remove_from_cart():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
        
    connection = create_connection()
    try:
        cursor = connection.cursor()
        data = request.json
        
        cursor.execute("""
            DELETE FROM cart 
            WHERE user_id = %s AND product_id = %s
        """, (session['user_id'], data['product_id']))
            
        connection.commit()
        return jsonify({'message': 'Removed from cart successfully'})
        
    except Error as e:
        print(f"Database error: {e}")
        return jsonify({'error': 'Database error'}), 500
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.route('/get_purchase_history', methods=['GET'])
def get_purchase_history():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
        
    connection = create_connection()
    try:
        cursor = connection.cursor(dictionary=True)
        
        # First check if user is a volunteer and get their highest badge
        cursor.execute("""
            SELECT role FROM users WHERE id = %s
        """, (session['user_id'],))
        user = cursor.fetchone()
        
        discount_percentage = 0
        if user and user['role'] == 'volunteer':
            # Get the highest badge for the volunteer
            cursor.execute("""
                SELECT badge_type 
                FROM volunteer_badges 
                WHERE volunteer_id = %s 
                ORDER BY FIELD(badge_type, 'bronze', 'gold', 'platinum', 'diamond') DESC 
                LIMIT 1
            """, (session['user_id'],))
            badge = cursor.fetchone()
            
            if badge:
                badge_discounts = {
                    'bronze': 5,
                    'gold': 10,
                    'platinum': 15,
                    'diamond': 20
                }
                discount_percentage = badge_discounts.get(badge['badge_type'].lower(), 0)
        
        # Get purchase history with product details
        cursor.execute("""
            SELECT 
                ph.*,
                p.name as product_name,
                p.image_path,
                p.price as original_price,
                pf.rating,
                pf.comment       
            FROM purchase_history ph
            JOIN products p ON ph.product_id = p.id
            LEFT JOIN product_feedback pf ON ph.id = pf.purchase_history_id
            WHERE ph.user_id = %s
            ORDER BY ph.purchase_date DESC
        """, (session['user_id'],))
        
        history = cursor.fetchall()
        
        # Process each history item
        for item in history:
            # Set image URL
            if item['image_path']:
                item['image_url'] = url_for('static', filename=f'uploads/{item["image_path"]}')
            else:
                item['image_url'] = url_for('static', filename='default-product.jpg')
            
            # Format date
            item['purchase_date'] = item['purchase_date'].strftime('%Y-%m-%d %H:%M:%S')
            
            # Calculate prices
            original_price = float(item['original_price'])
            item['price'] = original_price
            
            # Apply volunteer discount if applicable
            if discount_percentage > 0:
                item['discounted_price'] = round(original_price * (1 - discount_percentage/100), 2)
            else:
                item['discounted_price'] = None
                
        return jsonify(history)
        
    except Error as e:
        print(f"Database error in get_purchase_history: {str(e)}")
        return jsonify({'error': 'Database error'}), 500
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.route('/submit_product_feedback', methods=['POST'])
def submit_product_feedback():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    data = request.json
    purchase_id = data.get('purchase_id')
    rating = data.get('rating')
    comment = data.get('comment')
    product_id = data.get('product_id')
    
    if not all([purchase_id, rating, product_id]) or not (1 <= rating <= 5):
        return jsonify({'error': 'Invalid data'}), 400
    
    connection = create_connection()
    try:
        cursor = connection.cursor(dictionary=True)
        
        # Check if feedback already exists
        cursor.execute("""
            SELECT id FROM product_feedback 
            WHERE purchase_history_id = %s
        """, (purchase_id,))
        
        if cursor.fetchone():
            return jsonify({'error': 'Feedback already submitted'}), 400
        
        # Insert feedback
        cursor.execute("""
            INSERT INTO product_feedback 
            (purchase_history_id, user_id, product_id, rating, comment)
            VALUES (%s, %s, %s, %s, %s)
        """, (purchase_id, session['user_id'], product_id, rating, comment))
        
        connection.commit()
        return jsonify({'message': 'Feedback submitted successfully'})
        
    except Error as e:
        print(f"Database error in submit_feedback: {str(e)}")
        return jsonify({'error': 'Database error'}), 500
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.route('/get_product_feedback', methods=['GET'])
def get_all_product_feedback():
    """Returns feedback summary for all products"""
    connection = create_connection()
    if not connection:
        return jsonify({'success': False, 'error': 'Database connection failed'}), 500

    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("""
            SELECT 
                p.id, 
                p.product_name, 
                COALESCE(AVG(f.rating), 0) as average_rating, 
                COUNT(f.id) as feedback_count
            FROM products p
            LEFT JOIN product_feedback f ON p.id = f.product_id
            GROUP BY p.id, p.product_name
        """)
        products = cursor.fetchall()
        
        return jsonify({'success': True, 'products': products})

    except Exception as e:
        print(f"Database error: {e}")
        return jsonify({'success': False, 'error': 'Database error occurred'}), 500

    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()


@app.route('/get_product_feedback/<int:product_id>', methods=['GET'])
def get_product_feedback(product_id):
    """Returns detailed feedback for a single product"""
    if not product_id or product_id <= 0:
        return jsonify({'success': False, 'error': 'Invalid product ID'}), 400

    connection = create_connection()
    if not connection:
        return jsonify({'success': False, 'error': 'Database connection failed'}), 500

    try:
        cursor = connection.cursor(dictionary=True)

        # Fetch average rating and feedback count
        cursor.execute("""
            SELECT 
                COALESCE(AVG(rating), 0) AS average_rating,
                COUNT(*) AS feedback_count
            FROM product_feedback
            WHERE product_id = %s
        """, (product_id,))
        rating_data = cursor.fetchone()

        # Fetch latest feedback with user details
        cursor.execute("""
            SELECT 
                pf.comment, 
                pf.rating, 
                pf.created_at, 
                u.username
            FROM product_feedback pf
            JOIN users u ON pf.user_id = u.id
            WHERE pf.product_id = %s
            ORDER BY pf.created_at DESC
            LIMIT 5
        """, (product_id,))
        feedback = cursor.fetchall()

        return jsonify({
            'success': True,
            'average_rating': round(float(rating_data['average_rating']), 2),
            'feedback_count': rating_data['feedback_count'],
            'feedback': [{
                'username': item['username'],
                'rating': item['rating'],
                'comment': item['comment'],
                'date': item['created_at'].strftime('%Y-%m-%d %H:%M:%S')
            } for item in feedback] if feedback else []  
        })

    except Exception as e:
        print(f"Database error: {e}")
        return jsonify({'success': False, 'error': 'Database error occurred'}), 500

    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()
     

       
@app.route('/update_cart_quantity', methods=['POST'])
def update_cart_quantity():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
        
    data = request.json
    if not data or 'product_id' not in data or 'quantity' not in data:
        return jsonify({'error': 'Invalid request data'}), 400
        
    connection = create_connection()
    try:
        cursor = connection.cursor(dictionary=True)
        
        # First check product availability
        cursor.execute("""
            SELECT quantity FROM products 
            WHERE id = %s
        """, (data['product_id'],))
        
        product = cursor.fetchone()
        if not product:
            return jsonify({'error': 'Product not found'}), 404
            
        # Verify requested quantity is available and valid
        new_quantity = int(data['quantity'])
        if new_quantity < 1:
            return jsonify({'error': 'Quantity must be at least 1'}), 400
            
        if new_quantity > product['quantity']:
            return jsonify({'error': 'Requested quantity not available'}), 400
            
        # Update cart quantity
        cursor.execute("""
            UPDATE cart 
            SET quantity = %s
            WHERE user_id = %s AND product_id = %s
        """, (new_quantity, session['user_id'], data['product_id']))
            
        connection.commit()
        
        # Get updated cart total
        cursor.execute("""
            SELECT SUM(c.quantity * COALESCE(p.discounted_price, p.price)) as total
            FROM cart c
            JOIN products p ON c.product_id = p.id
            WHERE c.user_id = %s
        """, (session['user_id'],))
        
        result = cursor.fetchone()
        cart_total = result['total'] if result['total'] else 0
        
        return jsonify({
            'success': True,
            'message': 'Quantity updated successfully',
            'new_quantity': new_quantity,
            'cart_total': round(cart_total, 2)
        })
        
    except Error as e:
        print(f"Database error: {e}")
        return jsonify({'error': 'Database error'}), 500
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()
@app.route('/proceed_to_checkout', methods=['POST'])
def proceed_to_checkout():
    print("Proceed to checkout called") 
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'User not logged in'}), 401

    cart_data = request.json.get('cartItems', [])
    if not cart_data:
        return jsonify({'success': False, 'message': 'Cart is empty or invalid data'}), 400

    connection = create_connection()
    if connection is None:
        return jsonify({'success': False, 'message': 'Database connection failed'}), 500

    try:
        cursor = connection.cursor(dictionary=True)

        # Validate each cart item's stock
        for item in cart_data:
            product_id = item.get('product_id')
            quantity = item.get('quantity')

            if product_id is None or quantity is None:
                return jsonify({'success': False, 'message': 'Invalid cart item structure'}), 400

            # Check product stock
            cursor.execute("SELECT name, quantity FROM products WHERE id = %s", (product_id,))
            product = cursor.fetchone()

            if not product:
                return jsonify({'success': False, 'message': f"Product ID {product_id} does not exist"}), 404

            if product['quantity'] < quantity:
                return jsonify({'success': False, 'message': f"Insufficient stock for {product['name']}"}), 400

        # Save cart data in the session or proceed to checkout logic
        session['cart'] = cart_data

        return jsonify({'success': True, 'message': 'Proceeding to checkout'})

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()
@app.route('/process_cart_purchase', methods=['POST'])
def process_cart_purchase():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'User not logged in'}), 401
    
    connection = create_connection()
    if connection is None:
        return jsonify({'success': False, 'message': 'Database connection failed'}), 500
        
    try:
        cursor = connection.cursor(dictionary=True)
        
        # Start transaction
        connection.start_transaction()
        
        # Get cart items
        cursor.execute("""
            SELECT c.*, p.quantity as available_quantity, p.discounted_price
            FROM cart c
            JOIN products p ON c.product_id = p.id
            WHERE c.user_id = %s
        """, (session['user_id'],))
        
        cart_items = cursor.fetchall()
        
        if not cart_items:
            return jsonify({'success': False, 'message': 'No items in cart'}), 400
        
        # Calculate total amount
        total_amount = 0
        for item in cart_items:
            # Use discounted price if available, otherwise use original price
            price = item['discounted_price'] if item['discounted_price'] else item['price']
            total_amount += price * item['quantity']
        
        # Verify stock availability
        for item in cart_items:
            if item['quantity'] > item['available_quantity']:
                connection.rollback()
                return jsonify({
                    'success': False, 
                    'message': f'Insufficient stock for product: {item["product_name"]}'
                }), 400
        
        # Insert into purchase_history and update product quantities
        for item in cart_items:
            # Use discounted price if available, otherwise use original price
            final_price = item['discounted_price'] if item['discounted_price'] else item['price']
            
            # Create purchase history record
            cursor.execute("""
                INSERT INTO purchase_history 
                (user_id, product_id, product_name, price, quantity, discounted_price, total_amount)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (
                session['user_id'],
                item['product_id'],
                item['product_name'],
                final_price,
                item['quantity'],
                item['discounted_price'],
                final_price * item['quantity']  # Individual item total
            ))
            
            # Update product quantity
            cursor.execute("""
                UPDATE products 
                SET quantity = quantity - %s
                WHERE id = %s
            """, (item['quantity'], item['product_id']))
        
        # Clear cart
        cursor.execute("DELETE FROM cart WHERE user_id = %s", (session['user_id'],))
        
        # Commit transaction
        connection.commit()
        
        return jsonify({'success': True, 'message': 'Purchase completed successfully'})
        
    except Exception as e:
        connection.rollback()
        print(f"Error processing purchase: {str(e)}")  # For debugging
        return jsonify({'success': False, 'message': str(e)}), 500
        
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.route('/update_product_quantity', methods=['POST'])
def update_product_quantity():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
        
    connection = create_connection()
    try:
        cursor = connection.cursor(dictionary=True)
        data = request.json
        
        # Update product quantity
        cursor.execute("""
            UPDATE products 
            SET quantity = quantity - %s
            WHERE id = %s AND quantity >= %s
            RETURNING quantity, category
        """, (data['quantity'], data['product_id'], data['quantity']))
        
        result = cursor.fetchone()
        if not result:
            return jsonify({'error': 'Insufficient quantity'}), 400
            
        connection.commit()
        return jsonify({
            'message': 'Quantity updated successfully',
            'newQuantity': result['quantity'],
            'category': result['category']
        })
        
    except Error as e:
        print(f"Database error: {e}")
        return jsonify({'error': 'Database error'}), 500
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.route('/organiser/buyers')
def organiser_buyers():
    if 'user_id' not in session or session.get('role') != 'organiser':
        return redirect(url_for('login'))

    connection = create_connection()
    if connection is None:
        flash('Database connection failed.', 'error')
        return redirect(url_for('login'))

    try:
        cursor = connection.cursor(dictionary=True)
        
        # Fetch user details
        cursor.execute("SELECT * FROM users WHERE id = %s", (session['user_id'],))
        user = cursor.fetchone()

        cursor.execute("""
            SELECT 
                u.id AS buyer_id,
                u.username AS buyer_name,
                u.email AS buyer_email,
                u.mobile AS buyer_mobile,
                ph.product_name,
                ph.price,
                ph.quantity,
                ph.purchase_date
            FROM purchase_history ph
            JOIN users u ON ph.user_id = u.id
            JOIN products p ON ph.product_id = p.id
            WHERE p.organiser_id = %s
        """, (session['user_id'],))
        buyers = cursor.fetchall()

        return render_template('organiser.html', buyers=buyers, user=user)
    except Error as e:
        print(f"Database error: {e}")
        return str(e), 500
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.route('/get_organisers', methods=['GET'])
def get_organisers():
    connection = create_connection()
    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("""
            SELECT 
                u.id, 
                u.username, 
                u.email, 
                u.mobile, 
                u.location, 
                u.created_at, 
                COUNT(DISTINCT e.id) as total_events,
                COALESCE(SUM(e.products_recycled), 0) as total_products
            FROM users u
            LEFT JOIN events e ON u.id = e.organiser_id AND e.status = 'Completed'
            WHERE u.role = 'organiser'
            GROUP BY u.id, u.username, u.email, u.mobile, u.location, u.created_at
        """)
        organisers = cursor.fetchall()
        
        # Format the location for each organizer
        for organiser in organisers:
            if organiser['location']:
                # If the location is in latitude,longitude format, convert it
                if ',' in organiser['location']:
                    organiser['location'] = get_human_readable_location(organiser['location'])  # Pass location string
                # Else, keep the location as it is
            else:
                organiser['location'] = 'Location not specified'
        
        return jsonify({'success': True, 'organisers': organisers})
    except Exception as e:
        print("Error fetching organisers:", str(e))
        return jsonify({'success': False, 'message': str(e)})
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()
         


@app.route('/store_donor_info', methods=['POST'])
def store_donor_info():
    donor_info = request.json
    session['donor_info'] = donor_info
    return jsonify({'success': True})

@app.route('/confirm_payment', methods=['POST'])
def confirm_payment():
    data = request.json
    organiser_id = data.get('organiser_id')
    donor_info = session.get('donor_info')

    if not donor_info:
        return jsonify({'success': False, 'message': 'Donation data missing. Please restart the donation process.'})

    connection = create_connection()
    try:
        cursor = connection.cursor()
        cursor.execute("""
            INSERT INTO donations (donor_name, donor_email, donor_phone, amount, organiser_id, donation_date, status)
            VALUES (%s, %s, %s, %s, %s, NOW(), 'Pending')
        """, (
            donor_info['name'],
            donor_info['email'],
            donor_info['phone'],
            donor_info['amount'],
            organiser_id
        ))
        connection.commit()
        donation_id = cursor.lastrowid
        return jsonify({'success': True, 'donation_id': donation_id})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()


@app.route('/organiser/donors', methods=['GET'])
def organiser_donors():
    if 'user_id' not in session or session.get('role') != 'organiser':
        return redirect(url_for('login'))

    connection = create_connection()
    if connection is None:
        flash('Database connection failed.', 'error')
        return redirect(url_for('login'))

    try:
        cursor = connection.cursor(dictionary=True)
        
        # Debugging: Print organiser_id
        print(f"Organiser ID: {session['user_id']}")
        
        # Verify table schema and data
        cursor.execute("SHOW COLUMNS FROM donations")
        print("Donations Table Columns:", cursor.fetchall())
        
        # Comprehensive query with error handling
        cursor.execute("""
            SELECT 
                donor_name,
                donor_email,
                amount,
                donation_date,
                status
            FROM donations 
            WHERE organiser_id = %s
            ORDER BY donation_date DESC
        """, (session['user_id'],))
        
        donors = cursor.fetchall()
        
        # Debugging: Print raw donors data
        print("Raw Donors Data:", donors)

        return render_template('organiser.html', 
                               donors=donors,
                               show_donors_section=True)
                             
    except Exception as e:
        print(f"Detailed Database error: {e}")
        import traceback
        traceback.print_exc()
        donors = []
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

    return render_template('organiser.html', 
                           donors=donors, 
                           show_donors_section=True)



@app.route('/get_products')
def get_products():
    connection = create_connection()
    if connection is None:
        return jsonify({'success': False, 'message': 'Database connection failed'}), 500

    try:
        cursor = connection.cursor(dictionary=True)
        
        # Get search term from query parameters
        search_term = request.args.get('search', '').strip().lower()
        
        # Base query for products
        query = """
            SELECT p.*, u.username as organiser_name,
                   COUNT(ph.id) as purchase_count
            FROM products p
            JOIN users u ON p.organiser_id = u.id
            LEFT JOIN purchase_history ph ON p.id = ph.product_id
            WHERE p.status = 'Approved'
        """
        
        params = []
        
        # Add search condition if search term exists
        if search_term:
            query += """ AND (
                LOWER(p.name) LIKE %s 
                OR LOWER(p.description) LIKE %s
                OR LOWER(p.category) LIKE %s
            )"""
            search_pattern = f"%{search_term}%"
            params.extend([search_pattern, search_pattern, search_pattern])
            
        query += " GROUP BY p.id, u.username ORDER BY p.id DESC"
        
        cursor.execute(query, params)
        products = cursor.fetchall()

        if not products:
            return jsonify({'success': True, 'products': [], 'recommendations': []})

        # Apply discounts if applicable
        discount_percentage = 0
        if 'user_id' in session and session.get('role') == 'volunteer':
            cursor.execute("""
                SELECT badge_type 
                FROM volunteer_badges 
                WHERE volunteer_id = %s 
                ORDER BY FIELD(badge_type, 'bronze', 'gold', 'platinum', 'diamond') DESC 
                LIMIT 1
            """, (session['user_id'],))
            badge = cursor.fetchone()

            if badge and 'badge_type' in badge:
                badge_type = badge['badge_type']
                discount_map = {"bronze": 5, "gold": 10, "platinum": 15, "diamond": 20}
                discount_percentage = discount_map.get(badge_type.lower(), 0)

        # Process products
        processed_products = []
        all_recommendations = []
        
        # Calculate average price for price-based recommendations
        prices = [float(p['price']) for p in products if p['price'] is not None]
        avg_price = sum(prices) / len(prices) if prices else 0
        
        for product in products:
            try:
                # Convert price to float and handle None values
                original_price = float(product['price']) if product['price'] is not None else 0.0
                
                # Calculate discount if applicable
                if discount_percentage > 0:
                    discount_amount = (original_price * discount_percentage) / 100
                    discounted_price = round(original_price - discount_amount, 2)
                else:
                    discounted_price = None

                # Format quantity display
                if product['quantity'] is None:
                    formatted_quantity = "Not Available"
                elif product['category'] == 'wholesale':
                    formatted_quantity = f"{float(product['quantity']):.2f} kg"
                else:
                    formatted_quantity = f"{int(product['quantity'])} items"

                # Set image URL
                if product.get('image_path'):
                    image_url = url_for('static', filename=f'uploads/{product["image_path"]}')
                else:
                    image_url = url_for('static', filename='default-product.jpg')

                # Create processed product object
                processed_product = {
                    'id': product['id'],
                    'name': product['name'],
                    'description': product['description'],
                    'price': original_price,
                    'discounted_price': discounted_price,
                    'quantity': product['quantity'],
                    'formatted_quantity': formatted_quantity,
                    'category': product['category'],
                    'image_url': image_url,
                    'organiser_name': product['organiser_name'],
                    'status': product['status'],
                    'purchase_count': product.get('purchase_count', 0)
                }
                
                processed_products.append(processed_product)
                
                # Calculate recommendation score
                recommendation_score = 0
                
                # Search relevance (if search term exists)
                if search_term:
                    if search_term in product['name'].lower():
                        recommendation_score += 3
                    if search_term in product['description'].lower():
                        recommendation_score += 2
                    if search_term in product['category'].lower():
                        recommendation_score += 1
                
                # Popular products get higher score
                recommendation_score += min(product.get('purchase_count', 0), 5)
                
                # Products with price close to average get higher score
                price_diff = abs(original_price - avg_price)
                if price_diff <= avg_price * 0.2:  # Within 20% of average price
                    recommendation_score += 2
                
                # Products with available stock get higher score
                if product['quantity'] and float(product['quantity']) > 0:
                    recommendation_score += 1
                
                # Add to recommendations with score
                all_recommendations.append({
                    **processed_product,
                    'recommendation_score': recommendation_score
                })

            except Exception as e:
                print(f"Error processing product {product.get('id', 'unknown')}: {str(e)}")
                continue

        # Sort recommendations by score and take top 5
        all_recommendations.sort(key=lambda x: x.pop('recommendation_score'), reverse=True)
        recommendations = all_recommendations[:5]
        
        return jsonify({
            'success': True,
            'products': processed_products,
            'recommendations': recommendations,
            'discount_percentage': discount_percentage
        })

    except Exception as e:
        print(f"Error in get_products: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()


@app.route('/events')
def events():
    try:
        connection = create_connection()
        cursor = connection.cursor(dictionary=True)
        
        query = """
            SELECT e.*, u.username as organizer_name
            FROM events e
            JOIN users u ON e.organiser_id = u.id
            WHERE e.event_date >= CURDATE()
            ORDER BY e.event_date ASC, e.event_time ASC
        """
        cursor.execute(query)
        events = cursor.fetchall()
        
        # Process events
        for event in events:
            if isinstance(event["event_date"], timedelta):
                event["event_date"] = datetime.today() + event["event_date"]
            if isinstance(event["event_time"], timedelta):
                event["event_time"] = datetime.today() + event["event_time"]
            
            # Clean up photo path
            if event.get('photo_path'):
                # Remove any leading slashes or 'static/' from the path
                event['photo_path'] = event['photo_path'].strip().lstrip('/').replace('static/', '')

        return render_template('events.html', events=events, debug=app.debug)
        
    except Exception as e:
        print(f"Database error: {str(e)}")
        return render_template('events.html', 
                             events=[], 
                             debug=app.debug,
                             error_message="Unable to load events. Please try again later."), 500
        
    finally:
        if 'connection' in locals() and connection and connection.is_connected():
            cursor.close()
            connection.close()

'''
@app.route('/recommendations')
def get_recommendations():
    # Get the currently logged in user from session
    if 'user_id' not in session:
        return jsonify({'error': 'User not logged in'}), 401
    
    user_id = session['user_id']
    print(f"\n=== RECOMMENDATION REQUEST FOR USER {user_id} ===")
    connection = create_connection()
    
    try:
        cursor = connection.cursor(dictionary=True)
        
        # Fetch purchase history
        cursor.execute("SELECT user_id, product_id FROM purchase_history")
        purchase_data = cursor.fetchall()
        print("Purchase Data:", purchase_data)  # Debugging
        
        # If no purchase data at all in the system, show trending products
        if not purchase_data:
            print("No purchase history data found in the system")
            cursor.execute("""
                SELECT * FROM products 
                WHERE status = 'Approved' 
                ORDER BY created_at DESC 
                LIMIT 5
            """)
            recommended_items = cursor.fetchall()
            print("RECOMMENDATION TYPE: newest")
            print("FINAL RECOMMENDATIONS:", [item['id'] for item in recommended_items])
            return jsonify({'recommendations': recommended_items, 'type': 'newest'})
        
        # Convert to DataFrame for analysis
        df = pd.DataFrame(purchase_data)
        
        # Create user-product matrix
        user_product_matrix = df.pivot_table(index='user_id', columns='product_id', aggfunc='size', fill_value=0)
        print("User-Product Matrix:\n", user_product_matrix)  # Debugging
        
        # Calculate product popularity (total purchases per product)
        product_popularity = df['product_id'].value_counts().to_dict()
        popular_products = sorted(product_popularity.keys(), key=lambda x: product_popularity[x], reverse=True)[:5]
        print("Popular Products:", popular_products)
        
        # Check if user exists in purchase history
        if user_id not in user_product_matrix.index:
            print(f"User {user_id} not found in purchase history, showing popular products")
            
            # If we have popular products, use them
            if popular_products:
                format_strings = ','.join(['%s'] * len(popular_products))
                cursor.execute(f"""
                    SELECT * FROM products 
                    WHERE id IN ({format_strings}) 
                    AND status = 'Approved'
                """, tuple(popular_products))
                recommended_items = cursor.fetchall()
                
                # If no popular approved products, show newest products
                if not recommended_items:
                    print("No approved popular products found, falling back to newest")
                    cursor.execute("""
                        SELECT * FROM products 
                        WHERE status = 'Approved' 
                        ORDER BY created_at DESC 
                        LIMIT 5
                    """)
                    recommended_items = cursor.fetchall()
                
                print("RECOMMENDATION TYPE: popular")
                print("FINAL RECOMMENDATIONS:", [item['id'] for item in recommended_items])
                return jsonify({'recommendations': recommended_items, 'type': 'popular'})
        
        # User has purchase history - use collaborative filtering
        # Train KNN model
        model = NearestNeighbors(metric='cosine', algorithm='brute')
        model.fit(user_product_matrix)
        
        # Find similar users
        user_index = user_product_matrix.index.get_loc(user_id)
        n_neighbors = min(5, len(user_product_matrix))
        distances, indices = model.kneighbors([user_product_matrix.iloc[user_index]], n_neighbors=n_neighbors)
        
        print("Similar Users Found:", indices.flatten())  # Debugging
        similar_users = [user_product_matrix.index[i] for i in indices.flatten() if user_product_matrix.index[i] != user_id]
        print("Similar Users (excluding current user):", similar_users)
        
        # Get user's purchase history
        user_purchased = df[df['user_id'] == user_id]['product_id'].tolist()
        print("User Already Purchased:", user_purchased)  # Debugging
        
        # If no similar users found or only the user themselves, use popular products
        if not similar_users:
            print("No similar users found, showing popular products")
            if popular_products:
                # Filter out products user already purchased
                popular_not_purchased = [p for p in popular_products if p not in user_purchased]
                print("Popular products not yet purchased:", popular_not_purchased)
                
                if popular_not_purchased:
                    format_strings = ','.join(['%s'] * len(popular_not_purchased))
                    cursor.execute(f"""
                        SELECT * FROM products 
                        WHERE id IN ({format_strings}) 
                        AND status = 'Approved'
                    """, tuple(popular_not_purchased))
                else:
                    print("User has purchased all popular products, falling back to newest")
                    cursor.execute("""
                        SELECT * FROM products 
                        WHERE status = 'Approved' 
                        ORDER BY created_at DESC 
                        LIMIT 5
                    """)
                
                recommended_items = cursor.fetchall()
                print("RECOMMENDATION TYPE: popular")
                print("FINAL RECOMMENDATIONS:", [item['id'] for item in recommended_items])
                return jsonify({'recommendations': recommended_items, 'type': 'popular'})
        
        # Calculate product weights based on similar users' purchases
        product_weights = {}
        for sim_user in similar_users:
            sim_user_products = df[df['user_id'] == sim_user]['product_id'].tolist()
            for product in sim_user_products:
                if product not in user_purchased:  # Only recommend products user hasn't bought
                    if product in product_weights:
                        product_weights[product] += 1
                    else:
                        product_weights[product] = 1
        
        # Sort products by weight
        recommended_products = sorted(product_weights.keys(), key=lambda x: product_weights[x], reverse=True)
        print("Product weights based on similar users:", product_weights)
        print("Weighted Recommended Products:", recommended_products)  # Debugging
        
        # If no recommended products, fall back to popular products
        if not recommended_products:
            print("No specific recommendations found, showing popular products")
            # Filter out products user already purchased
            popular_not_purchased = [p for p in popular_products if p not in user_purchased]
            print("Popular products not yet purchased:", popular_not_purchased)
            
            if popular_not_purchased:
                format_strings = ','.join(['%s'] * len(popular_not_purchased))
                cursor.execute(f"""
                    SELECT * FROM products 
                    WHERE id IN ({format_strings}) 
                    AND status = 'Approved'
                """, tuple(popular_not_purchased))
            else:
                print("User has purchased all popular products, falling back to newest")
                cursor.execute("""
                    SELECT * FROM products 
                    WHERE status = 'Approved' 
                    ORDER BY created_at DESC 
                    LIMIT 5
                """)
        else:
            # Limit to top 5 recommendations
            recommended_products = recommended_products[:5]
            print("Top 5 recommended products:", recommended_products)
            # Safe SQL Query
            format_strings = ','.join(['%s'] * len(recommended_products))
            cursor.execute(f"""
                SELECT * FROM products 
                WHERE id IN ({format_strings}) 
                AND status = 'Approved'
            """, tuple(recommended_products))
        
        recommended_items = cursor.fetchall()
        print("Products found in database:", len(recommended_items))
        
        # Final fallback if no recommendations
        if not recommended_items:
            print("No approved recommendations found, showing newest products")
            cursor.execute("""
                SELECT * FROM products 
                WHERE status = 'Approved' 
                ORDER BY created_at DESC 
                LIMIT 5
            """)
            recommended_items = cursor.fetchall()
            print("RECOMMENDATION TYPE: newest (fallback)")
            print("FINAL RECOMMENDATIONS:", [item['id'] for item in recommended_items])
            return jsonify({'recommendations': recommended_items, 'type': 'newest'})
        
        print("RECOMMENDATION TYPE: personalized")
        print("FINAL RECOMMENDATIONS:", [item['id'] for item in recommended_items])
        return jsonify({'recommendations': recommended_items, 'type': 'personalized'})
    
    except Exception as e:
        print("ERROR in recommendation engine:", str(e))
        print(traceback.format_exc())  # Add the full traceback for debugging
        return jsonify({'error': str(e), 'type': 'error'}), 500
    
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()
        print("=== RECOMMENDATION REQUEST COMPLETED ===\n")'''

def train_xgboost_model():
    connection = create_connection()
    cursor = connection.cursor(dictionary=True)
    
    # Fetch ALL data from `product_feedback` with join to get actual user and product IDs
    cursor.execute("""
        SELECT pf.user_id, pf.product_id, pf.rating, 
               p.category, p.price, ph.purchase_date
        FROM product_feedback pf
        JOIN purchase_history ph ON pf.purchase_history_id = ph.id
        JOIN products p ON pf.product_id = p.id
    """)
    data = cursor.fetchall()
    
    if not data:
        print("No data available for training")
        return None, None, None, None
    
    print(f"Training with {len(data)} feedback records")
    
    # Convert to DataFrame
    df = pd.DataFrame(data)
    
    # Add date features (days since purchase)
    df['purchase_date'] = pd.to_datetime(df['purchase_date'])
    current_date = pd.Timestamp.now()
    df['days_since_purchase'] = (current_date - df['purchase_date']).dt.days
    
    # Add price bands as a feature
    df['price_band'] = pd.qcut(df['price'], q=5, labels=False)
    
    # Check if we have enough data per user
    user_counts = df.groupby('user_id').size()
    valid_users = user_counts[user_counts >= 3].index.tolist()
    
    if len(valid_users) < 5:
        print(f"Warning: Only {len(valid_users)} users have 3+ ratings. Model may lack personalization.")
    else:
        print(f"{len(valid_users)} users have 3+ ratings, good for personalization")
    
    # Print distribution of ratings
    print("Rating distribution:")
    print(df['rating'].value_counts())
    
    # Map ratings more effectively
    original_ratings = sorted(df['rating'].unique())
    print(f"Original unique ratings in data: {original_ratings}")
    
    # Create a mapping from original ratings to 0-based indices
    rating_to_index = {rating: idx for idx, rating in enumerate(original_ratings)}
    index_to_rating = {idx: rating for rating, idx in rating_to_index.items()}
    num_classes = len(rating_to_index)
    
    print(f"Rating to index mapping: {rating_to_index}")
    print(f"Number of classes: {num_classes}")
    
    # Transform ratings to 0-based indices using the mapping
    df['shifted_rating'] = df['rating'].map(rating_to_index)
    
    # Encode categorical variables
    le_user = LabelEncoder()
    le_product = LabelEncoder()
    le_category = LabelEncoder()
    
    df['user_id'] = le_user.fit_transform(df['user_id'])
    df['product_id'] = le_product.fit_transform(df['product_id'])
    df['category'] = le_category.fit_transform(df['category'])
    
    print(f"Training with {len(le_user.classes_)} unique users")
    print(f"Training with {len(le_product.classes_)} unique products")
    
    # Create feature matrix with more features for personalization
    X = df[['user_id', 'product_id', 'category', 'price_band', 'days_since_purchase']]
    y = df['shifted_rating']  # Use the shifted ratings (0-based indices)
    
    # Check for data imbalance
    if len(df) < 100:
        print("WARNING: Limited data for training, model may not perform well")
    
    # Train/Test Split using the transformed ratings
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Create XGBoost DMatrix objects
    dtrain = xgb.DMatrix(X_train, label=y_train)
    dtest = xgb.DMatrix(X_test, label=y_test)
    
    # Train using XGBoost API with more parameters
    param = {
        'max_depth': 6, 
        'eta': 0.3, 
        'objective': 'multi:softprob',
        'num_class': num_classes,
        'eval_metric': 'mlogloss',
        'subsample': 0.8,  # Use 80% of data per tree - prevents overfitting
        'colsample_bytree': 0.8,  # Use 80% of features per tree - increases diversity
        'min_child_weight': 3,  # Require more observations per node - prevents overfitting
        'reg_lambda': 1.0,  # L2 regularization
        'reg_alpha': 0.0,  # L1 regularization
    }
    
    num_round = 100
    evallist = [(dtrain, 'train'), (dtest, 'eval')]
    model = xgb.train(param, dtrain, num_round, evals=evallist, early_stopping_rounds=10, verbose_eval=True)
    
    # Save model, encoders, and rating mappings
    model.save_model("xgboost_model.json")
    joblib.dump(le_user, "le_user.pkl")
    joblib.dump(le_product, "le_product.pkl")
    joblib.dump(le_category, "le_category.pkl")
    
    # Save rating mapping information and additional metadata
    rating_info = {
        "rating_to_index": rating_to_index,
        "index_to_rating": index_to_rating,
        "num_classes": num_classes,
        "original_ratings": original_ratings,
        "training_date": str(current_date),
        "num_users": len(le_user.classes_),
        "num_products": len(le_product.classes_)
    }
    joblib.dump(rating_info, "rating_info.pkl")
    
    # Add feature importance analysis
    importance = model.get_score(importance_type='gain')
    importance_df = pd.DataFrame({'feature': list(importance.keys()), 'importance': list(importance.values())})
    importance_df = importance_df.sort_values('importance', ascending=False)
    print("\nFeature importance:")
    print(importance_df)
    
    print("Model training completed and saved!")
    return model, le_user, le_product, rating_info

# Load Model
def load_model():
    try:
        model = xgb.Booster()
        model.load_model("xgboost_model.json")
        le_user = joblib.load("le_user.pkl")
        le_product = joblib.load("le_product.pkl")
        rating_info = joblib.load("rating_info.pkl")
        print("Model loaded successfully!")
        return model, le_user, le_product, rating_info
    except Exception as e:
        print(f"Error loading model: {e}")
        return None, None, None, None

def get_xgboost_recommendations(user_id):
    # Create a consistent user-specific seed at the start
    user_seed = hash(str(user_id))
    random.seed(user_seed)
    np.random.seed(user_seed % 2**32)  # np.random requires a 32-bit seed
    
    model, le_user, le_product, rating_info = load_model()
    if model is None:
        print("Model not loaded, training a new one")
        model, le_user, le_product, rating_info = train_xgboost_model()
        if model is None:
            return {'error': 'Failed to train model'}, 500
    
    try:
        connection = create_connection()
        cursor = connection.cursor(dictionary=True)
        
        # Debug: Print all users and their encoding to verify user differentiation
        print(f"Processing recommendations for user_id: {user_id}")
        
        # Check if user exists in training data
        if user_id not in le_user.classes_:
            print(f"User {user_id} not found in training data, falling back to popular products")
            # Fallback to popular products with user-specific ordering
            cursor.execute("""
                SELECT DISTINCT p.* FROM products p
                JOIN purchase_history ph ON p.id = ph.product_id
                WHERE p.status = 'Approved'
                GROUP BY p.id
                ORDER BY (p.id * %s) %% 100, COUNT(*) DESC
                LIMIT 8
            """, (user_id,))
            popular_items = cursor.fetchall()
            # Add selection based on user_id
            if len(popular_items) > 5:
                popular_items = popular_items[:5]
            return {'recommendations': popular_items, 'type': 'popularity_fallback_new_user'}
        
        # Encode user ID
        user_encoded = le_user.transform([user_id])[0]
        print(f"User {user_id} encoded as {user_encoded}")
        
        # Get user's purchase history first
        cursor.execute("""
            SELECT DISTINCT product_id 
            FROM purchase_history 
            WHERE user_id = %s
        """, (user_id,))
        purchased_products = [item['product_id'] for item in cursor.fetchall()]
        print(f"User has purchased {len(purchased_products)} products")
        
        # If the user has no purchase history, we can't make personalized recommendations
        if not purchased_products:
            print(f"User {user_id} has no purchase history, using popularity model with user-specific ordering")
            
            cursor.execute("""
                SELECT DISTINCT p.* FROM products p
                WHERE p.status = 'Approved'
                ORDER BY (p.id * %s) %% 100, p.popularity_score DESC, p.created_at DESC
                LIMIT 10
            """, (user_id,))
            popular_items = cursor.fetchall()
            if len(popular_items) > 5:
                popular_items = popular_items[:5]
            elif not popular_items:
                cursor.execute("""
                    SELECT DISTINCT * FROM products 
                    WHERE status = 'Approved'
                    ORDER BY (id * %s) %% 100, created_at DESC
                    LIMIT 5
                """, (user_id,))
                popular_items = cursor.fetchall()
            
            return {'recommendations': popular_items, 'type': 'popularity_no_history'}
        
        # Get all available products to recommend (exclude purchased ones)
        placeholders = ','.join(['%s'] * len(purchased_products))
        cursor.execute(f"""
            SELECT DISTINCT id, category, price FROM products 
            WHERE status = 'Approved' 
            AND id NOT IN ({placeholders})
        """, tuple(purchased_products))
        available_products_data = cursor.fetchall()
        
        # Critical Fix: If there are no available products to recommend, fall back to general products
        if not available_products_data:
            print(f"No available products to recommend for user {user_id}")
            
            cursor.execute("""
                SELECT DISTINCT * FROM products 
                WHERE status = 'Approved'
                ORDER BY (id * %s) %% 100, created_at DESC
                LIMIT 5
            """, (user_id,))
            fallback_items = cursor.fetchall()
            
            return {'recommendations': fallback_items, 'type': 'general_fallback'}
        
        # Create a map of product data for easy access
        product_data = {item['id']: item for item in available_products_data}
        available_products = [item['id'] for item in available_products_data]
        
        # Now we need to:
        # 1. Only predict for products the user hasn't purchased
        # 2. Only include products that are available in the encoded product list
        available_product_indices = []
        available_product_ids = []
        
        for product_id in available_products:
            if product_id in le_product.classes_:
                available_product_indices.append(le_product.transform([product_id])[0])
                available_product_ids.append(product_id)
        
        # If no available products are in the model, fall back with user-specific ordering
        if not available_product_indices:
            print(f"No available products in model for user {user_id}")
            
            cursor.execute("""
                SELECT DISTINCT * FROM products 
                WHERE status = 'Approved'
                ORDER BY (id * %s) %% 100, created_at DESC
                LIMIT 10
            """, (user_id,))
            new_items = cursor.fetchall()
            
            # Select a subset for user-specific results
            if len(new_items) > 5:
                new_items = new_items[:5]
                
            return {'recommendations': new_items, 'type': 'new_products_fallback'}
        
        # Get user's previous feedback for better personalization
        cursor.execute("""
            SELECT ph.product_id, pf.rating 
            FROM purchase_history ph
            LEFT JOIN product_feedback pf ON ph.id = pf.purchase_history_id
            WHERE ph.user_id = %s AND pf.rating IS NOT NULL
        """, (user_id,))
        user_ratings = {item['product_id']: item['rating'] for item in cursor.fetchall()}
        
        # Prepare input data for prediction - include more features
        user_products = []
        for i, product_id_encoded in enumerate(available_product_indices):
            product_id = available_product_ids[i]
            product_info = product_data[product_id]
            
            # Get category if available
            category_encoded = 0
            if hasattr(le_category, 'transform') and 'category' in product_info:
                try:
                    category_encoded = le_category.transform([product_info['category']])[0]
                except:
                    pass
            
            # Determine price band (1-5)
            price_band = 2  # Default to middle band
            if 'price' in product_info and product_info['price'] is not None:
                # Simple price banding logic - adjust based on your actual price ranges
                price = float(product_info['price'])
                if price < 100:
                    price_band = 0
                elif price < 500:
                    price_band = 1
                elif price < 1000:
                    price_band = 2
                elif price < 5000:
                    price_band = 3
                else:
                    price_band = 4
            
            # Add days since purchase - use a reasonable default
            days_since_purchase = 30  # Default value
            
            user_products.append({
                'user_id': user_encoded,
                'product_id': product_id_encoded,
                'category': category_encoded,
                'price_band': price_band,
                'days_since_purchase': days_since_purchase
            })
        
        user_products_df = pd.DataFrame(user_products)
        print(f"Predicting for {len(user_products_df)} products with full feature set")
        
        # Convert to DMatrix for prediction
        dpredict = xgb.DMatrix(user_products_df)
        
        # Get prediction probabilities for all classes
        all_probs = model.predict(dpredict)
        # Reshape to match (n_samples, n_classes)
        all_probs = all_probs.reshape(len(user_products_df), -1)
        
        # Calculate weighted score using original rating values
        weighted_scores = np.zeros(len(available_product_indices))
        index_to_rating = rating_info["index_to_rating"]
        
        for idx in range(rating_info["num_classes"]):
            # Map back to original rating value for weighting
            original_rating = index_to_rating[idx]
            weighted_scores += all_probs[:, idx] * original_rating
        
        # Create recommendations DataFrame for better manipulation
        recommendations_df = pd.DataFrame({
            'product_id': available_product_ids,  # Use actual product IDs
            'score': weighted_scores
        })
        
        # Get category and price preferences for enhanced personalization
        cursor.execute("""
            SELECT p.category, COUNT(*) as count, AVG(COALESCE(pf.rating, 3)) as avg_rating
            FROM purchase_history ph
            JOIN products p ON ph.product_id = p.id
            LEFT JOIN product_feedback pf ON ph.id = pf.purchase_history_id
            WHERE ph.user_id = %s
            GROUP BY p.category
            ORDER BY avg_rating DESC, count DESC
        """, (user_id,))
        
        category_prefs = cursor.fetchall()
        preferred_categories = [item['category'] for item in category_prefs]
        
        print(f"User preferred categories: {preferred_categories}")
        
        # Apply category boost
        for idx, row in recommendations_df.iterrows():
            product_id = row['product_id']
            if product_id in product_data:
                category = product_data[product_id].get('category')
                if category and category in preferred_categories:
                    position = preferred_categories.index(category)
                    # Higher boost for more preferred categories
                    boost = max(0.5, (len(preferred_categories) - position) * 0.4)
                    recommendations_df.at[idx, 'score'] *= (1 + boost)
        
        # Add diversity factor - slightly penalize products that are too similar
        # This encourages different types of products in recommendations
        seen_categories = set()
        for idx, row in recommendations_df.iterrows():
            product_id = row['product_id']
            if product_id in product_data:
                category = product_data[product_id].get('category')
                if category:
                    if category in seen_categories:
                        # Apply small penalty to products in categories we've already seen
                        recommendations_df.at[idx, 'score'] *= 0.95
                    seen_categories.add(category)
        
        # Get top recommended product IDs
        recommendations_df = recommendations_df.sort_values('score', ascending=False)
        
        # Get at least twice as many as we need for proper filtering
        recommended_products = recommendations_df['product_id'].unique().tolist()[:20]
        
        print(f"Recommended products before filtering: {len(recommended_products)}")
        
        # Fetch product details
        if recommended_products:
            format_strings = ','.join(['%s'] * len(recommended_products))
            cursor.execute(
                f"SELECT DISTINCT * FROM products WHERE id IN ({format_strings}) AND status = 'Approved'", 
                tuple(recommended_products)
            )
            recommended_items = cursor.fetchall()
            
            # Sort the recommended items based on the order in recommended_products
            recommended_items_sorted = []
            product_map = {item['id']: item for item in recommended_items}
            for pid in recommended_products:
                if pid in product_map:
                    recommended_items_sorted.append(product_map[pid])
            
            # Ensure no duplicate products by ID
            seen_ids = set()
            unique_items = []
            for item in recommended_items_sorted:
                if item['id'] not in seen_ids:
                    seen_ids.add(item['id'])
                    unique_items.append(item)
            
            # Limit to 10 items
            if len(unique_items) > 10:
                unique_items = unique_items[:10]
            
            print(f"Recommendations for user {user_id} completed with {len(unique_items)} unique items")
            
            # Reset random seeds before returning
            random.seed()
            np.random.seed(None)
            
            if unique_items:
                return {'recommendations': unique_items, 'type': 'xgboost_personalized'}
        
        # If we reached here, fallback to popular products with user-specific ordering
        cursor.execute("""
            SELECT DISTINCT p.* FROM products p
            WHERE p.status = 'Approved'
            ORDER BY (p.id * %s) %% 100, p.created_at DESC
            LIMIT 10
        """, (user_id,))
        fallback_items = cursor.fetchall()
        
        # Reset random seeds
        random.seed()
        np.random.seed(None)
        
        return {'recommendations': fallback_items, 'type': 'final_fallback'}
        
    except Exception as e:
        print(f"Error generating recommendations: {e}")
        traceback.print_exc()
        
        # Reset random seeds
        random.seed()
        np.random.seed(None)
        
        # Return a simple error fallback
        try:
            connection = create_connection()
            cursor = connection.cursor(dictionary=True)
            
            cursor.execute("""
                SELECT DISTINCT * FROM products 
                WHERE status = 'Approved'
                ORDER BY created_at DESC
                LIMIT 5
            """)
            error_fallback = cursor.fetchall()
            
            return {'recommendations': error_fallback, 'type': 'error_fallback', 'error': str(e)}
        except:
            return {'error': str(e), 'recommendations': []}, 500

# API Endpoints
@app.route('/train', methods=['GET'])
def train():
    try:
        train_xgboost_model()
        return jsonify({'message': 'Model trained successfully!'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/recommendations', methods=['GET'])
def recommendations():
    user_id = request.args.get('user_id')
    if not user_id:
        return jsonify({'error': 'User ID required'}), 400
    
    try:
        # Convert user_id to integer if it's a numeric string
        if user_id.isdigit():
            user_id = int(user_id)
        return jsonify(get_xgboost_recommendations(user_id))
    except Exception as e:
        return jsonify({'error': str(e)}), 500




@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(debug=True)