from flask import Blueprint, render_template, request, jsonify, session, flash, redirect, url_for
from mysql.connector import Error
from functools import wraps
from database import create_connection, execute_query, close_connection # Assuming you have your database connection in a separate file

# Create blueprint
donation_bp = Blueprint('donation', __name__)

# Routes
@donation_bp.route('/donation')
def donation_page():
    return render_template('donation.html')

@donation_bp.route('/process_donation', methods=['POST'])
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
    
    # Store donor information in session for next step
    session['donor_info'] = donor_info
    
    return jsonify({
        'success': True,
        'redirect': url_for('donation.select_organizer')
    })

@donation_bp.route('/select_organizser')
def select_organiser():
    if 'donor_info' not in session:
        return redirect(url_for('donation.donation_page'))
    
    connection = create_connection()
    if connection is None:
        flash('Database connection failed.', 'error')
        return redirect(url_for('donation.donation_page'))
    
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
                SUM(e.plastics_collected) as total_plastics_collected
            FROM users u
            LEFT JOIN events e ON u.id = e.organiser_id
            WHERE u.role = 'organiser'
            GROUP BY u.id
        """)
        
        organizers = cursor.fetchall()
        
        return render_template('select_organiser.html',
                             donor_info=session['donor_info'],
                             organizers=organizers)
    
    except Error as e:
        print(f"Database error: {e}")
        return str(e), 500
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@donation_bp.route('/finalize_donation', methods=['POST'])
def finalize_donation():
    if 'donor_info' not in session:
        return jsonify({'success': False, 'message': 'Donation information not found'}), 400
    
    organizer_id = request.form.get('organizer_id')
    if not organizer_id:
        return jsonify({'success': False, 'message': 'No organizer selected'}), 400
    
    connection = create_connection()
    try:
        cursor = connection.cursor()
        
        # Insert donation record
        cursor.execute("""
            INSERT INTO donations (
                donor_name, donor_email, donor_phone,
                amount, organizer_id, donation_date
            ) VALUES (%s, %s, %s, %s, %s, NOW())
        """, (
            session['donor_info']['name'],
            session['donor_info']['email'],
            session['donor_info']['phone'],
            session['donor_info']['amount'],
            organizer_id
        ))
        
        connection.commit()
        
        # Clear donation info from session
        session.pop('donor_info', None)
        
        return jsonify({
            'success': True,
            'message': 'Donation processed successfully',
            'redirect': url_for('donation.donation_confirmation')
        })
        
    except Error as e:
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()