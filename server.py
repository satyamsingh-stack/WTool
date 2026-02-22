from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import os
import pandas as pd
import urllib.parse
import time
import webbrowser
import pyautogui as gui
from PIL import Image
from io import BytesIO
import win32clipboard
from datetime import datetime, timedelta
app = Flask(__name__)

# Helper function for clipboard operations
def send_to_clipboard(clip_type, data):
    win32clipboard.OpenClipboard()
    win32clipboard.EmptyClipboard()
    win32clipboard.SetClipboardData(clip_type, data)
    win32clipboard.CloseClipboard()

# Configure the app
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['JWT_SECRET_KEY'] = 'your_secret_key_here'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.secret_key = 'your_secret_key_here'

# Ensure the upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
jwt = JWTManager(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    expiration_time = db.Column(db.DateTime, nullable=True)
    is_admin = db.Column(db.Boolean, default=False)  # New column for admin flag

# Create the database
with app.app_context():
    db.create_all()

# Create a default admin user
with app.app_context():
    if not User.query.filter_by(username='admin').first():
        admin_user = User(
            username='admin',
            password=generate_password_hash('admin123', method='pbkdf2:sha256'),
            is_admin=True
        )
        db.session.add(admin_user)
        db.session.commit()

@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('upload_file'))
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    data = request.form
    user = User.query.filter_by(username=data['username']).first()
    if user and check_password_hash(user.password, data['password']):
        if user.expiration_time and user.expiration_time < datetime.utcnow():
            return render_template('login.html', error='Your credentials have expired. Please contact the admin.')
        session['username'] = user.username
        session['login_time'] = datetime.utcnow().isoformat()  # Store login time
        # Store expiration time for the timer (only for non-admin users)
        # Append 'Z' to indicate UTC timezone
        if user.expiration_time and not user.is_admin:
            session['expiration_time'] = user.expiration_time.isoformat() + 'Z'
        else:
            session['expiration_time'] = None
        if user.is_admin:
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('upload_file'))
    return render_template('login.html', error='Invalid credentials')

@app.route('/admin', methods=['GET', 'POST'])
def admin_dashboard():
    if 'username' not in session:
        return redirect(url_for('home'))

    user = User.query.filter_by(username=session['username']).first()
    if not user or not user.is_admin:
        return redirect(url_for('home'))

    if request.method == 'POST':
        data = request.form
        hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
        
        days = int(data.get('days', 0))
        hours = int(data.get('hours', 0))
        minutes = int(data.get('minutes', 0))
        expiration_time = datetime.utcnow() + timedelta(days=days, hours=hours, minutes=minutes)
        
        new_user = User(
            username=data['username'],
            password=hashed_password,
            expiration_time=expiration_time
        )
        db.session.add(new_user)
        db.session.commit()
        flash('User created successfully!', 'success')

    users = User.query.all()
    current_time = datetime.utcnow()
    
    # Calculate stats
    total_users = len(users)
    active_users = sum(1 for u in users if u.expiration_time and u.expiration_time > current_time)
    expired_users = total_users - active_users
    
    user = User.query.filter_by(username=session['username']).first()
    expiration_time = None
    is_admin = False
    if user:
        is_admin = user.is_admin
        if user.expiration_time and not user.is_admin:
            # Append 'Z' to indicate UTC timezone
            expiration_time = user.expiration_time.isoformat() + 'Z'
    
    return render_template('admin.html', users=users, current_time=current_time, 
                          total_users=total_users, active_users=active_users, expired_users=expired_users,
                          login_time=session.get('login_time'), expiration_time=expiration_time, is_admin=is_admin)

@app.route('/admin/delete/<int:user_id>')
def delete_user(user_id):
    if 'username' not in session:
        return redirect(url_for('home'))
    
    admin_user = User.query.filter_by(username=session['username']).first()
    if not admin_user or not admin_user.is_admin:
        return redirect(url_for('home'))
    
    user_to_delete = User.query.get(user_id)
    if user_to_delete and not user_to_delete.is_admin:
        db.session.delete(user_to_delete)
        db.session.commit()
        flash('User deleted successfully!', 'success')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/api/expiration')
def get_expiration_time():
    if 'username' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    user = User.query.filter_by(username=session['username']).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    if user.is_admin:
        return jsonify({'expiration_time': None})
    
    if user.expiration_time:
        # Append 'Z' to indicate UTC timezone
        return jsonify({
            'expiration_time': user.expiration_time.isoformat() + 'Z',
            'is_expired': user.expiration_time < datetime.utcnow()
        })
    
    return jsonify({'expiration_time': None})

@app.route('/admin/update/<int:user_id>', methods=['POST'])
def update_user(user_id):
    if 'username' not in session:
        return redirect(url_for('home'))
    
    admin_user = User.query.filter_by(username=session['username']).first()
    if not admin_user or not admin_user.is_admin:
        return redirect(url_for('home'))
    
    user_to_update = User.query.get(user_id)
    if user_to_update:
        days = request.form.get('days')
        hours = request.form.get('hours', 0)
        minutes = request.form.get('minutes', 0)
        
        if days and days.strip():
            days = int(days)
            hours = int(hours) if hours else 0
            minutes = int(minutes) if minutes else 0
            user_to_update.expiration_time = datetime.utcnow() + timedelta(days=days, hours=hours, minutes=minutes)
        
        new_password = request.form.get('new_password')
        if new_password:
            user_to_update.password = generate_password_hash(new_password, method='pbkdf2:sha256')
        
        db.session.commit()
        flash('User updated successfully!', 'success')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    # Check expiration first
    is_valid, error_msg = check_expiration()
    if not is_valid:
        if 'username' in session:
            session.pop('username', None)
        session.pop('file_path', None)
        session.pop('image_path', None)
        return render_template('upload.html', error='Your credentials have expired. Please log in again.')

    if request.method == 'POST':
        if 'file' not in request.files or 'image' not in request.files:
            return render_template('upload.html', error='Please upload both Excel file and image (optional).')

        file = request.files['file']
        image = request.files['image']

        if file.filename == '':
            return render_template('upload.html', error='No Excel file selected for uploading.')

        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)
        session['file_path'] = file_path

        if image.filename != '':
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], image.filename)
            image.save(image_path)
            session['image_path'] = image_path
        else:
            session['image_path'] = None

        return redirect(url_for('send_message'))

    user = User.query.filter_by(username=session['username']).first()
    expiration_time = None
    is_admin = False
    if user:
        is_admin = user.is_admin
        if user.expiration_time and not user.is_admin:
            # Append 'Z' to indicate UTC timezone
            expiration_time = user.expiration_time.isoformat() + 'Z'
    
    return render_template('upload.html', login_time=session.get('login_time'), expiration_time=expiration_time, is_admin=is_admin)

# Global variable to track message-sending state
is_sending_messages = False

@app.route('/logout')
def logout():
    global is_sending_messages
    session.pop('username', None)
    session.pop('file_path', None)
    is_sending_messages = False  # Stop sending messages
    return redirect(url_for('home'))

def check_expiration():
    """Check if user's credentials have expired"""
    if 'username' not in session:
        return False, 'Not logged in'
    
    user = User.query.filter_by(username=session['username']).first()
    if not user:
        return False, 'User not found'
    
    if user.is_admin:
        return True, None
    
    if user.expiration_time and user.expiration_time < datetime.utcnow():
        return False, 'Credentials expired'
    
    return True, None

@app.route('/send', methods=['GET', 'POST'])
def send_message():
    global is_sending_messages
    
    # Check expiration FIRST on every request
    is_valid, error_msg = check_expiration()
    if not is_valid:
        if 'username' in session:
            session.pop('username', None)
        session.pop('file_path', None)
        session.pop('image_path', None)
        is_sending_messages = False
        return render_template('send.html', error='Your credentials have expired. Please log in again.')
    
    if 'file_path' not in session:
        return redirect(url_for('home'))

    if request.method == 'POST':
        message = request.form['message']
        file_path = session['file_path']
        image_path = session.get('image_path')

        # URL-encode the message for large messages - THIS IS THE KEY FIX!
        try:
            encoded_message = urllib.parse.quote(message)
        except Exception:
            return render_template('send.html', error='Given Message is not supported! No emojis please!')

        if encoded_message == "" and image_path == "":
            return render_template('send.html', error='Please type or attach a message')

        try:
            df = pd.read_excel(file_path)
            numbers = [str(ele).strip() for ele in df.iloc[:, 6] if len(str(ele)) > 5]
            # Store message in session for pyautogui to use
            session['bulk_message'] = message

            is_sending_messages = True
            first_message = True
            num_count = len(numbers)
            
            # If no image, use URL-encoded message in URL (like working code)
            if image_path == "":
                for i, number in enumerate(numbers[:3000]):
                    if not is_sending_messages:  # Stop if the user logs out
                        return render_template('send.html', error='Message sending stopped.')

                    if i == 0:
                        # First message - open WhatsApp Web
                        webbrowser.open("https://web.whatsapp.com")
                        time.sleep(30)
                        gui.keyDown('ctrl')
                        gui.press('w')
                        gui.keyUp('ctrl')
                        time.sleep(8)
                    
                    # Use URL-encoded message in URL - THIS IS THE KEY FIX FOR LARGE MESSAGES!
                    url = "https://web.whatsapp.com/send?phone={}&text={}&source&data&app_absent".format(number, encoded_message)
                    webbrowser.open(url)
                    time.sleep(50)
                    gui.press('enter')
                    time.sleep(3)
                    
                    # Close tab and open new chat
                    gui.keyDown('ctrl')
                    gui.press('w')
                    gui.keyUp('ctrl')
                    time.sleep(1)
                    gui.press('enter')
                    
                    if i == num_count - 1:  # Last element
                        time.sleep(2)
                    else:
                        time.sleep(8)
            else:
                # With image - use clipboard for image, but still use URL-encoded message
                image_success = True
                filepath = image_path
                try:
                    image = Image.open(filepath)
                    output = BytesIO()
                    image.convert("RGB").save(output, "BMP")
                    data = output.getvalue()[14:]
                    output.close()
                    send_to_clipboard(win32clipboard.CF_DIB, data)
                except Exception:
                    return render_template('send.html', error='Not suitable attachment')

                for i, number in enumerate(numbers[:3000]):
                    if not is_sending_messages:  # Stop if the user logs out
                        return render_template('send.html', error='Message sending stopped.')

                    if i == 0:
                        # First message - open WhatsApp Web
                        webbrowser.open("https://web.whatsapp.com")
                        time.sleep(35)
                        gui.keyDown('ctrl')
                        gui.press('w')
                        gui.keyUp('ctrl')
                        time.sleep(8)
                    
                    # Use URL-encoded message in URL
                    url = "https://web.whatsapp.com/send?phone={}&text={}&source&data&app_absent".format(number, encoded_message)
                    webbrowser.open(url)
                    time.sleep(60)
                    
                    # Paste image from clipboard
                    gui.keyDown('ctrl')
                    gui.press('v')
                    gui.keyUp('ctrl')
                    time.sleep(5)
                    gui.press('enter')
                    time.sleep(3)
                    
                    # Close tab and open new chat
                    gui.keyDown('ctrl')
                    gui.press('w')
                    gui.keyUp('ctrl')
                    time.sleep(1)
                    gui.press('enter')
                    
                    if i == num_count - 1:  # Last element
                        time.sleep(2)
                    else:
                        time.sleep(8)

            is_sending_messages = False
            return render_template('send.html', success='Messages sent successfully!')

        except Exception as e:
            is_sending_messages = False
            return render_template('send.html', error=f'Error: {str(e)}')

    user = User.query.filter_by(username=session['username']).first()
    expiration_time = None
    is_admin = False
    if user:
        is_admin = user.is_admin
        if user.expiration_time and not user.is_admin:
            # Append 'Z' to indicate UTC timezone
            expiration_time = user.expiration_time.isoformat() + 'Z'
    
    return render_template('send.html', login_time=session.get('login_time'), expiration_time=expiration_time, is_admin=is_admin)

if __name__ == '__main__':
    app.run(debug=True)
