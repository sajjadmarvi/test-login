from flask import Flask, render_template_string, request, redirect, flash, session, jsonify, url_for
import os
import json
import bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_socketio import SocketIO, emit
from celery import Celery
import boto3
import logging
from logging.handlers import RotatingFileHandler
from config import Config, DevelopmentConfig, ProductionConfig
from datetime import datetime, timedelta
import telebot
import threading
import secrets

app = Flask(__name__)
app.config.from_object(DevelopmentConfig if os.environ.get('FLASK_ENV') == 'development' else ProductionConfig)
app.secret_key = 'your_secret_key_here'  # کلید مخفی برای session

# Initialize extensions
socketio = SocketIO(app)

# Initialize Limiter with In-Memory storage
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri="memory://"
)

# Configure logging
handler = RotatingFileHandler('app.log', maxBytes=10000, backupCount=3)
handler.setLevel(logging.INFO)
app.logger.addHandler(handler)

# Initialize Celery
def make_celery(app):
    celery = Celery(app.import_name, backend=app.config['CELERY_RESULT_BACKEND'],
                    broker=app.config['CELERY_BROKER_URL'])
    celery.conf.update(app.config)
    return celery

celery = make_celery(app)

# Telegram Bot Token and ID
TELEGRAM_BOT_TOKEN = 'your-bot-token'
TELEGRAM_BOT_ID = '@your_id_bot'
TELEGRAM_USER_ID = 1234567891  # Your Telegram User ID plese change this id
bot = telebot.TeleBot(TELEGRAM_BOT_TOKEN)

# Helper functions
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def upload_to_s3(file_name, bucket, object_name=None):
    if object_name is None:
        object_name = file_name
    s3 = boto3.client('s3', aws_access_key_id=app.config['AWS_ACCESS_KEY'],
                      aws_secret_access_key=app.config['AWS_SECRET_KEY'])
    try:
        s3.upload_file(file_name, bucket, object_name)
    except Exception as e:
        app.logger.error(f"Error uploading to S3: {e}")
        return False
    return True

# Load and save data to JSON file
def load_data():
    if os.path.exists('data.json'):
        try:
            with open('data.json', 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError:
            print("Corrupted data.json file. Creating a new one.")
            default_data = {'users': [], 'password_reset_tokens': {}, 'recovery_requests': []}
            save_data(default_data)
            return default_data
    return {'users': [], 'password_reset_tokens': {}, 'recovery_requests': []}

def save_data(data):
    with open('data.json', 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4)

def backup_data():
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_filename = f"backup_data_{timestamp}.json"
    data = load_data()
    with open(backup_filename, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4)
    return backup_filename

# Log user actions and send to Telegram
def log_action(username, ip_address, action):
    log_entry = {
        'username': username,
        'ip_address': ip_address,
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'action': action
    }
    logs = []
    if os.path.exists('logs.json'):
        with open('logs.json', 'r', encoding='utf-8') as file:
            logs = json.load(file)
    logs.append(log_entry)
    with open('logs.json', 'w', encoding='utf-8') as file:
        json.dump(logs, file, indent=4)
    
    # Send log to Telegram
    try:
        message = f"📝 *New Log Entry*\n\n👤 *Username*: {username}\n🌐 *IP Address*: {ip_address}\n⏰ *Timestamp*: {log_entry['timestamp']}\n🔧 *Action*: {action}"
        bot.send_message(TELEGRAM_USER_ID, message, parse_mode='Markdown')
    except Exception as e:
        app.logger.error(f"Error sending log to Telegram: {e}")

# Load and save chat messages
def load_chat_messages():
    if os.path.exists('chat_messages.json'):
        try:
            with open('chat_messages.json', 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError:
            return []
    return []

def save_chat_messages(messages):
    with open('chat_messages.json', 'w', encoding='utf-8') as f:
        json.dump(messages, f, indent=4)

# Load and save password recovery requests
def load_recovery_requests():
    if os.path.exists('recovery_requests.json'):
        try:
            with open('recovery_requests.json', 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError:
            return []
    return []

def save_recovery_requests(requests):
    with open('recovery_requests.json', 'w', encoding='utf-8') as f:
        json.dump(requests, f, indent=4)

# Generate a secure token for password reset
def generate_password_reset_token(username):
    token = secrets.token_urlsafe(32)
    data = load_data()
    data['password_reset_tokens'][token] = {
        'username': username,
        'expires': (datetime.now() + timedelta(hours=1)).isoformat()
    }
    save_data(data)
    return token

# Send password reset link via Telegram
def send_password_reset_link(telegram_id, reset_link):
    try:
        message = f"برای بازیابی رمز عبور خود، روی لینک زیر کلیک کنید:\n{reset_link}\n\nاگر ربات را استارت نکرده‌اید، ابتدا ربات را از طریق لینک زیر استارت کنید:\nhttps://t.me/{TELEGRAM_BOT_ID}"
        bot.send_message(telegram_id, message)
        return True
    except Exception as e:
        app.logger.error(f"Error sending message via Telegram: {e}")
        return False

# Routes
@app.route('/')
def login():
    return render_template_string(LOGIN_PAGE)

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def do_login():
    username = request.form['username']
    password = request.form['password']
    data = load_data()
    user = next((u for u in data['users'] if u['username'] == username), None)
    if user and check_password(password, user['password']):
        session['username'] = user['username']
        session['role'] = user['role']
        log_action(username, request.remote_addr, "Successful Login")
        flash('Login successful!', 'success')
        if user['role'] == 'admin':
            return redirect('/mrhjf')
        return redirect('/chat')
    else:
        log_action(username, request.remote_addr, "Failed Login Attempt")
        flash('Invalid username or password', 'danger')
    return redirect('/')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        telegram_id = request.form['telegram_id']
        
        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect('/signup')
        
        data = load_data()
        if any(u['username'] == username for u in data['users']):
            flash('Username already exists!', 'danger')
            return redirect('/signup')
        
        # Generate a random code and send it to the user's Telegram ID
        verification_code = secrets.token_hex(3)
        try:
            bot.send_message(telegram_id, f"Your verification code is: {verification_code}")
        except Exception as e:
            app.logger.error(f"Error sending verification code to Telegram: {e}")
            flash('Error sending verification code. Please check your Telegram ID.', 'danger')
            return redirect('/signup')
        
        # Store the verification code in the session
        session['verification_code'] = verification_code
        session['signup_data'] = {
            'username': username,
            'password': hash_password(password),
            'telegram_id': telegram_id,
            'role': 'user',
            'max_attempts': 3
        }
        
        return redirect('/verify_telegram')
    return render_template_string(SIGNUP_PAGE)

@app.route('/signup_guide')
def signup_guide():
    return render_template_string(SIGNUP_GUIDE_PAGE)

@app.route('/verify_telegram', methods=['GET', 'POST'])
def verify_telegram():
    if request.method == 'POST':
        user_code = request.form['verification_code']
        if 'verification_code' in session and user_code == session['verification_code']:
            data = load_data()
            data['users'].append(session['signup_data'])
            save_data(data)
            log_action(session['signup_data']['username'], request.remote_addr, "New User Signup")
            flash('Account created successfully! Please log in.', 'success')
            session.pop('verification_code', None)
            session.pop('signup_data', None)
            return redirect('/')
        else:
            flash('Invalid verification code', 'danger')
    return render_template_string(VERIFY_TELEGRAM_PAGE)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form['username']
        data = load_data()
        user = next((u for u in data['users'] if u['username'] == username), None)
        if user:
            # Generate a password reset token
            token = generate_password_reset_token(username)
            reset_link = url_for('reset_password', token=token, _external=True)
            
            # Send the reset link via Telegram
            send_password_reset_link(user['telegram_id'], reset_link)
            
            # Log the recovery request
            recovery_request = {
                'username': username,
                'telegram_id': user['telegram_id'],
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            recovery_requests = load_recovery_requests()
            recovery_requests.append(recovery_request)
            save_recovery_requests(recovery_requests)
            
            flash(f'A password reset link has been sent to your Telegram ID: {user["telegram_id"]}', 'success')
        else:
            flash('Invalid username', 'danger')
        return redirect('/forgot_password')
    return render_template_string(FORGOT_PASSWORD_PAGE)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    data = load_data()
    token_data = data['password_reset_tokens'].get(token)
    
    if not token_data or datetime.fromisoformat(token_data['expires']) < datetime.now():
        flash('Invalid or expired token', 'danger')
        return redirect('/forgot_password')
    
    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        if new_password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('reset_password', token=token))
        
        user = next((u for u in data['users'] if u['username'] == token_data['username']), None)
        if user:
            user['password'] = hash_password(new_password)
            save_data(data)
            del data['password_reset_tokens'][token]
            save_data(data)
            flash('Your password has been reset successfully!', 'success')
            return redirect('/')
    
    return render_template_string(RESET_PASSWORD_PAGE, token=token)

@app.route('/chat')
def chat():
    if 'username' not in session:
        return redirect('/')
    return render_template_string(CHAT_PAGE, username=session['username'])

@app.route('/success')
def success():
    if 'username' not in session:
        return redirect('/')
    return render_template_string(SUCCESS_PAGE, ip_address=request.remote_addr)

@app.route('/logout')
def logout():
    log_action(session.get('username'), request.remote_addr, "Logout")
    session.clear()
    return redirect('/')

# Admin Routes
@app.route('/mrhjf')
def mrhjf():
    if session.get('role') != 'admin':
        return redirect('/')
    return render_template_string(ADMIN_PAGE)

@app.route('/mrhjf/logs')
def mrhjf_logs():
    if session.get('role') != 'admin':
        return redirect('/')
    logs = []
    if os.path.exists('logs.json'):
        with open('logs.json', 'r', encoding='utf-8') as file:
            logs = json.load(file)
    return render_template_string(LOGS_PAGE, logs=logs)

@app.route('/mrhjf/reports')
def mrhjf_reports():
    if session.get('role') != 'admin':
        return redirect('/')
    logs = []
    if os.path.exists('logs.json'):
        with open('logs.json', 'r', encoding='utf-8') as file:
            logs = json.load(file)
    total_logins = len(logs)
    failed_logins = len([log for log in logs if log['action'] != "Successful Login"])
    unique_ips = len(set(log['ip_address'] for log in logs))
    return render_template_string(REPORTS_PAGE, total_logins=total_logins, failed_logins=failed_logins, unique_ips=unique_ips)

@app.route('/mrhjf/access_control')
def mrhjf_access_control():
    if session.get('role') != 'admin':
        return redirect('/')
    data = load_data()
    return render_template_string(ACCESS_CONTROL_PAGE, users=data['users'])

@app.route('/mrhjf/update_access', methods=['POST'])
def mrhjf_update_access():
    if session.get('role') != 'admin':
        return redirect('/')
    username = request.form.get('username')
    role = request.form.get('role')
    password = request.form.get('password')
    max_attempts = request.form.get('max_attempts')
    data = load_data()
    user = next((u for u in data['users'] if u['username'] == username), None)
    if user:
        user['role'] = role
        if password:
            user['password'] = hash_password(password)  # تغییر پسورد
        if max_attempts:
            user['max_attempts'] = int(max_attempts)  # تغییر تعداد تلاش‌ها
        save_data(data)
        log_action(session.get('username'), request.remote_addr, f"Updated Access for {username}")
    return redirect('/mrhjf/access_control')

@app.route('/mrhjf/add_user', methods=['POST'])
def add_user():
    if session.get('role') != 'admin':
        return redirect('/')
    full_admin_password = request.form.get('full_admin_password')
    if full_admin_password != 'alireza@9931':
        flash('Invalid full admin password', 'danger')
        return redirect('/mrhjf/access_control')
    
    username = request.form.get('username')
    password = request.form.get('password')
    telegram_id = request.form.get('telegram_id')
    role = request.form.get('role')
    max_attempts = request.form.get('max_attempts')
    
    data = load_data()
    if any(u['username'] == username for u in data['users']):
        flash('Username already exists!', 'danger')
        return redirect('/mrhjf/access_control')
    
    new_user = {
        'username': username,
        'password': hash_password(password),
        'telegram_id': telegram_id,
        'role': role,
        'max_attempts': int(max_attempts)
    }
    data['users'].append(new_user)
    save_data(data)
    log_action(session.get('username'), request.remote_addr, f"Added new user: {username}")
    flash('User added successfully!', 'success')
    return redirect('/mrhjf/access_control')

@app.route('/mrhjf/delete_user', methods=['POST'])
def delete_user():
    if session.get('role') != 'admin':
        return redirect('/')
    full_admin_password = request.form.get('full_admin_password')
    if full_admin_password != 'alireza@9931':
        flash('Invalid full admin password', 'danger')
        return redirect('/mrhjf/access_control')
    
    username = request.form.get('username')
    data = load_data()
    data['users'] = [u for u in data['users'] if u['username'] != username]
    save_data(data)
    log_action(session.get('username'), request.remote_addr, f"Deleted user: {username}")
    flash('User deleted successfully!', 'success')
    return redirect('/mrhjf/access_control')

@app.route('/mrhjf/search_logs')
def mrhjf_search_logs():
    if session.get('role') != 'admin':
        return redirect('/')
    query = request.args.get('query', '')
    logs = []
    if os.path.exists('logs.json'):
        with open('logs.json', 'r', encoding='utf-8') as file:
            logs = json.load(file)
    filtered_logs = [log for log in logs if query.lower() in log['username'].lower() or query.lower() in log['ip_address'].lower()]
    return render_template_string(SEARCH_LOGS_PAGE, logs=filtered_logs, query=query)

@app.route('/mrhjf/real_time_logs')
def mrhjf_real_time_logs():
    if session.get('role') != 'admin':
        return redirect('/')
    return render_template_string(REAL_TIME_LOGS_PAGE)

@app.route('/mrhjf/chat_logs')
def mrhjf_chat_logs():
    if session.get('role') != 'admin':
        return redirect('/')
    chat_messages = load_chat_messages()
    return render_template_string(CHAT_LOGS_PAGE, chat_messages=chat_messages)

@app.route('/mrhjf/real_time_chat')
def mrhjf_real_time_chat():
    if session.get('role') != 'admin':
        return redirect('/')
    return render_template_string(REAL_TIME_CHAT_PAGE)

@app.route('/mrhjf/recovery_requests')
def mrhjf_recovery_requests():
    if session.get('role') != 'admin':
        return redirect('/')
    recovery_requests = load_recovery_requests()
    return render_template_string(RECOVERY_REQUESTS_PAGE, recovery_requests=recovery_requests)

@app.route('/mrhjf/view_decoded_passwords', methods=['POST'])
def view_decoded_passwords():
    if session.get('role') != 'admin':
        return redirect('/')
    full_admin_password = request.form.get('full_admin_password')
    if full_admin_password != 'alireza@9931':
        flash('Invalid full admin password', 'danger')
        return redirect('/mrhjf/access_control')
    
    data = load_data()
    decoded_passwords = []
    for user in data['users']:
        decoded_passwords.append({
            'username': user['username'],
            'password': user['password']
        })
    return render_template_string(DECODED_PASSWORDS_PAGE, passwords=decoded_passwords)

@app.route('/mrhjf/backup', methods=['POST'])
def backup():
    if session.get('role') != 'admin':
        return redirect('/')
    backup_filename = backup_data()
    log_action(session.get('username'), request.remote_addr, f"Backup created: {backup_filename}")
    flash(f'Backup created successfully: {backup_filename}', 'success')
    return redirect('/mrhjf')

# WebSocket for chat
@socketio.on('send_message')
def handle_send_message(data):
    username = session.get('username')
    recipient = data.get('recipient')
    message = data.get('message')
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    if username and recipient and message:
        chat_message = {
            'sender': username,
            'recipient': recipient,
            'message': message,
            'timestamp': timestamp
        }
        messages = load_chat_messages()
        messages.append(chat_message)
        save_chat_messages(messages)
        
        emit('receive_message', chat_message, broadcast=True)

# HTML Templates
LOGIN_PAGE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .password-toggle {
            cursor: pointer;
            position: absolute;
            right: 10px;
            top: 50%;
            transform: translateY(-50%);
        }
    </style>
</head>
<body>
    <div class="container d-flex justify-content-center align-items-center min-vh-100">
        <div class="card p-4 shadow-sm" style="width: 100%; max-width: 350px;">
            <h3 class="text-center mb-3">Login</h3>
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    {% for category, message in messages %}
                        <div class="alert alert-{{ category }}">{{ message }}</div>
                    {% endfor %}
                {% endif %}
            {% endwith %}
            <form action="/login" method="POST">
                <div class="mb-3">
                    <input type="text" name="username" class="form-control" placeholder="Username" required>
                </div>
                <div class="mb-3 position-relative">
                    <input type="password" name="password" id="password" class="form-control" placeholder="Password" required>
                    <span class="password-toggle" onclick="togglePassword()">👁️</span>
                </div>
                <button type="submit" class="btn btn-primary w-100">Log In</button>
            </form>
            <p class="text-center mt-3">Don't have an account? <a href="/signup">Sign up</a></p>
            <p class="text-center mt-3"><a href="/forgot_password">Forgot Password?</a></p>
        </div>
    </div>
    <script>
        function togglePassword() {
            const passwordField = document.getElementById('password');
            if (passwordField.type === 'password') {
                passwordField.type = 'text';
            } else {
                passwordField.type = 'password';
            }
        }
    </script>
</body>
</html>
'''

SIGNUP_PAGE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign Up</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container d-flex justify-content-center align-items-center min-vh-100">
        <div class="card p-4 shadow-sm" style="width: 100%; max-width: 350px;">
            <h3 class="text-center mb-3">Sign Up</h3>
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    {% for category, message in messages %}
                        <div class="alert alert-{{ category }}">{{ message }}</div>
                    {% endfor %}
                {% endif %}
            {% endwith %}
            <form action="/signup" method="POST">
                <div class="mb-3">
                    <input type="text" name="username" class="form-control" placeholder="Username" required>
                </div>
                <div class="mb-3">
                    <input type="password" name="password" class="form-control" placeholder="Password" required>
                </div>
                <div class="mb-3">
                    <input type="password" name="confirm_password" class="form-control" placeholder="Confirm Password" required>
                </div>
                <div class="mb-3">
                    <input type="text" name="telegram_id" class="form-control" placeholder="Telegram ID" required>
                </div>
                <div class="mb-3">
                    <a href="/signup_guide" class="btn btn-info w-100">How to get Telegram ID?</a>
                </div>
                <button type="submit" class="btn btn-primary w-100">Sign Up</button>
            </form>
            <p class="text-center mt-3">Already have an account? <a href="/">Log in</a></p>
        </div>
    </div>
</body>
</html>
'''

SIGNUP_GUIDE_PAGE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign Up Guide</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container d-flex justify-content-center align-items-center min-vh-100">
        <div class="card p-4 shadow-sm" style="width: 100%; max-width: 800px;">
            <h3 class="text-center mb-3">How to get your Telegram ID</h3>
            <p>To get your Telegram ID, follow these steps:</p>
            <ol>
                <li>Open Telegram and search for the bot <a href="https://t.me/useninfobot">@useninfobot</a>.</li>
                <li>Start the bot by clicking the "Start" button.</li>
                <li>The bot will send you your Telegram ID. Make sure to copy it.</li>
                <li>Return to the signup page and enter your Telegram ID in the "Telegram ID" field.</li>
            </ol>
            <p class="text-center mt-3"><a href="/signup" class="btn btn-secondary">Back to Sign Up</a></p>
        </div>
    </div>
</body>
</html>
'''

VERIFY_TELEGRAM_PAGE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verify Telegram</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container d-flex justify-content-center align-items-center min-vh-100">
        <div class="card p-4 shadow-sm" style="width: 100%; max-width: 350px;">
            <h3 class="text-center mb-3">Verify Telegram</h3>
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    {% for category, message in messages %}
                        <div class="alert alert-{{ category }}">{{ message }}</div>
                    {% endfor %}
                {% endif %}
            {% endwith %}
            <form action="/verify_telegram" method="POST">
                <div class="mb-3">
                    <input type="text" name="verification_code" class="form-control" placeholder="Verification Code" required>
                </div>
                <button type="submit" class="btn btn-primary w-100">Verify</button>
            </form>
        </div>
    </div>
</body>
</html>
'''

FORGOT_PASSWORD_PAGE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forgot Password</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container d-flex justify-content-center align-items-center min-vh-100">
        <div class="card p-4 shadow-sm" style="width: 100%; max-width: 350px;">
            <h3 class="text-center mb-3">Forgot Password</h3>
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    {% for category, message in messages %}
                        <div class="alert alert-{{ category }}">{{ message }}</div>
                    {% endfor %}
                {% endif %}
            {% endwith %}
            <form action="/forgot_password" method="POST">
                <div class="mb-3">
                    <input type="text" name="username" class="form-control" placeholder="Username" required>
                </div>
                <button type="submit" class="btn btn-primary w-100">Recover Password</button>
            </form>
        </div>
    </div>
</body>
</html>
'''

RESET_PASSWORD_PAGE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Password</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container d-flex justify-content-center align-items-center min-vh-100">
        <div class="card p-4 shadow-sm" style="width: 100%; max-width: 350px;">
            <h3 class="text-center mb-3">Reset Password</h3>
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    {% for category, message in messages %}
                        <div class="alert alert-{{ category }}">{{ message }}</div>
                    {% endfor %}
                {% endif %}
            {% endwith %}
            <form action="/reset_password/{{ token }}" method="POST">
                <div class="mb-3">
                    <input type="password" name="new_password" class="form-control" placeholder="New Password" required>
                </div>
                <div class="mb-3">
                    <input type="password" name="confirm_password" class="form-control" placeholder="Confirm New Password" required>
                </div>
                <button type="submit" class="btn btn-primary w-100">Reset Password</button>
            </form>
        </div>
    </div>
</body>
</html>
'''

CHAT_PAGE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Chat</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            background-color: #1e1e1e;
            color: #ffffff;
            font-family: 'Arial', sans-serif;
        }
        .chat-box {
            height: 400px;
            overflow-y: scroll;
            border: 1px solid #444;
            padding: 10px;
            margin-bottom: 10px;
            background-color: #2d2d2d;
            border-radius: 5px;
        }
        .message {
            padding: 8px;
            margin-bottom: 10px;
            border-radius: 5px;
            background-color: #3a3a3a;
        }
        .message strong {
            color: #4caf50;
        }
        .message em {
            color: #888;
            font-size: 0.9em;
        }
        .form-control {
            background-color: #2d2d2d;
            color: #ffffff;
            border: 1px solid #444;
        }
        .form-control:focus {
            background-color: #3a3a3a;
            color: #ffffff;
            border-color: #4caf50;
        }
        .btn-primary {
            background-color: #4caf50;
            border: none;
        }
        .btn-primary:hover {
            background-color: #45a049;
        }
    </style>
</head>
<body>
    <div class="container d-flex justify-content-center align-items-center min-vh-100">
        <div class="card p-4 shadow-sm" style="width: 100%; max-width: 800px; background-color: #2d2d2d;">
            <h3 class="text-center mb-3">Chat</h3>
            <div id="chat-box" class="chat-box">
                <!-- Chat messages will appear here -->
            </div>
            <form id="chat-form">
                <div class="mb-3">
                    <input type="text" id="recipient" class="form-control" placeholder="Recipient (Username)" required>
                </div>
                <div class="mb-3">
                    <textarea id="message" class="form-control" placeholder="Type your message here..." required></textarea>
                </div>
                <button type="submit" class="btn btn-primary w-100">Send</button>
            </form>
            <p class="text-center mt-3"><a href="/logout" class="btn btn-danger">Logout</a></p>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <script>
        const socket = io();
        const chatBox = document.getElementById('chat-box');
        const chatForm = document.getElementById('chat-form');

        // Receive messages
        socket.on('receive_message', function(data) {
            const messageElement = document.createElement('div');
            messageElement.className = 'message';
            messageElement.innerHTML = `<strong>${data.sender}</strong> to <strong>${data.recipient}</strong>: ${data.message} <em>(${data.timestamp})</em>`;
            chatBox.appendChild(messageElement);
            chatBox.scrollTop = chatBox.scrollHeight;
        });

        // Send messages
        chatForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const recipient = document.getElementById('recipient').value;
            const message = document.getElementById('message').value;
            if (recipient && message) {
                socket.emit('send_message', { recipient, message });
                document.getElementById('message').value = '';
            }
        });
    </script>
</body>
</html>
'''

SUCCESS_PAGE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Success</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container d-flex justify-content-center align-items-center min-vh-100">
        <div class="card p-4 shadow-sm" style="width: 100%; max-width: 350px;">
            <h3 class="text-center mb-3">Success</h3>
            <p>Your IP: {{ ip_address }}</p>
            <a href="/logout" class="btn btn-danger w-100">Logout</a>
        </div>
    </div>
</body>
</html>
'''

ADMIN_PAGE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Panel</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container d-flex justify-content-center align-items-center min-vh-100">
        <div class="card p-4 shadow-sm" style="width: 100%; max-width: 800px;">
            <h3 class="text-center mb-3">Admin Panel</h3>
            <a href="/mrhjf/logs" class="btn btn-info mb-2">View Logs</a>
            <a href="/mrhjf/reports" class="btn btn-warning mb-2">View Reports</a>
            <a href="/mrhjf/access_control" class="btn btn-success mb-2">Access Control</a>
            <a href="/mrhjf/search_logs" class="btn btn-primary mb-2">Search Logs</a>
            <a href="/mrhjf/real_time_logs" class="btn btn-secondary mb-2">Real-Time Logs</a>
            <a href="/mrhjf/chat_logs" class="btn btn-dark mb-2">View Chat Logs</a>
            <a href="/mrhjf/real_time_chat" class="btn btn-light mb-2">Real-Time Chat</a>
            <a href="/mrhjf/recovery_requests" class="btn btn-danger mb-2">View Recovery Requests</a>
            <form action="/mrhjf/backup" method="POST" style="display:inline;">
                <button type="submit" class="btn btn-dark mb-2">Backup Data</button>
            </form>
            <a href="/logout" class="btn btn-danger w-100">Logout</a>
        </div>
    </div>
</body>
</html>
'''

LOGS_PAGE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Logs</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container d-flex justify-content-center align-items-center min-vh-100">
        <div class="card p-4 shadow-sm" style="width: 100%; max-width: 1200px;">
            <h3 class="text-center mb-3">Admin Logs</h3>
            <table class="table">
                <thead>
                    <tr>
                        <th>Username</th>
                        <th>IP Address</th>
                        <th>Timestamp</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    {% for log in logs %}
                    <tr>
                        <td>{{ log.username }}</td>
                        <td>{{ log.ip_address }}</td>
                        <td>{{ log.timestamp }}</td>
                        <td>{{ log.action }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            <p class="text-center mt-3"><a href="/mrhjf" class="btn btn-secondary">Back to Admin Panel</a></p>
        </div>
    </div>
</body>
</html>
'''

REPORTS_PAGE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Reports</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container d-flex justify-content-center align-items-center min-vh-100">
        <div class="card p-4 shadow-sm" style="width: 100%; max-width: 800px;">
            <h3 class="text-center mb-3">Admin Reports</h3>
            <p>Total Logins: {{ total_logins }}</p>
            <p>Failed Logins: {{ failed_logins }}</p>
            <p>Unique IPs: {{ unique_ips }}</p>
            <p class="text-center mt-3"><a href="/mrhjf" class="btn btn-secondary">Back to Admin Panel</a></p>
        </div>
    </div>
</body>
</html>
'''

ACCESS_CONTROL_PAGE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Control</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container d-flex justify-content-center align-items-center min-vh-100">
        <div class="card p-4 shadow-sm" style="width: 100%; max-width: 800px;">
            <h3 class="text-center mb-3">Access Control</h3>
            <table class="table">
                <thead>
                    <tr>
                        <th>Username</th>
                        <th>Role</th>
                        <th>Password</th>
                        <th>Max Attempts</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {% for user in users %}
                    <tr>
                        <td>{{ user.username }}</td>
                        <td>{{ user.role }}</td>
                        <td>••••••••</td>
                        <td>{{ user.max_attempts }}</td>
                        <td>
                            <form action="/mrhjf/update_access" method="POST" style="display:inline;">
                                <input type="hidden" name="username" value="{{ user.username }}">
                                <select name="role" class="form-select">
                                    <option value="user" {% if user.role == 'user' %}selected{% endif %}>User</option>
                                    <option value="admin" {% if user.role == 'admin' %}selected{% endif %}>Admin</option>
                                </select>
                                <input type="password" name="password" class="form-control" placeholder="New Password">
                                <input type="number" name="max_attempts" class="form-control" placeholder="Max Attempts">
                                <button type="submit" class="btn btn-warning btn-sm">Update</button>
                            </form>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            <form action="/mrhjf/view_decoded_passwords" method="POST" class="mt-3">
                <input type="password" name="full_admin_password" class="form-control" placeholder="Enter Full Admin Password">
                <button type="submit" class="btn btn-danger w-100 mt-2">View Decoded Passwords</button>
            </form>
            <form action="/mrhjf/add_user" method="POST" class="mt-3">
                <input type="password" name="full_admin_password" class="form-control" placeholder="Enter Full Admin Password">
                <input type="text" name="username" class="form-control" placeholder="Username">
                <input type="password" name="password" class="form-control" placeholder="Password">
                <input type="text" name="telegram_id" class="form-control" placeholder="Telegram ID">
                <select name="role" class="form-select">
                    <option value="user">User</option>
                    <option value="admin">Admin</option>
                </select>
                <input type="number" name="max_attempts" class="form-control" placeholder="Max Attempts">
                <button type="submit" class="btn btn-success w-100 mt-2">Add User</button>
            </form>
            <form action="/mrhjf/delete_user" method="POST" class="mt-3">
                <input type="password" name="full_admin_password" class="form-control" placeholder="Enter Full Admin Password">
                <input type="text" name="username" class="form-control" placeholder="Username">
                <button type="submit" class="btn btn-danger w-100 mt-2">Delete User</button>
            </form>
            <p class="text-center mt-3"><a href="/mrhjf" class="btn btn-secondary">Back to Admin Panel</a></p>
        </div>
    </div>
</body>
</html>
'''

DECODED_PASSWORDS_PAGE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Decoded Passwords</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container d-flex justify-content-center align-items-center min-vh-100">
        <div class="card p-4 shadow-sm" style="width: 100%; max-width: 800px;">
            <h3 class="text-center mb-3">Decoded Passwords</h3>
            <table class="table">
                <thead>
                    <tr>
                        <th>Username</th>
                        <th>Password</th>
                    </tr>
                </thead>
                <tbody>
                    {% for password in passwords %}
                    <tr>
                        <td>{{ password.username }}</td>
                        <td>{{ password.password }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            <p class="text-center mt-3"><a href="/mrhjf" class="btn btn-secondary">Back to Admin Panel</a></p>
        </div>
    </div>
</body>
</html>
'''

SEARCH_LOGS_PAGE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Search Logs</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container d-flex justify-content-center align-items-center min-vh-100">
        <div class="card p-4 shadow-sm" style="width: 100%; max-width: 1200px;">
            <h3 class="text-center mb-3">Search Logs</h3>
            <form action="/mrhjf/search_logs" method="GET">
                <div class="mb-3">
                    <input type="text" name="query" class="form-control" placeholder="Search by username or IP" required>
                </div>
                <button type="submit" class="btn btn-primary w-100">Search</button>
            </form>
            <table class="table mt-3">
                <thead>
                    <tr>
                        <th>Username</th>
                        <th>IP Address</th>
                        <th>Timestamp</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    {% for log in logs %}
                    <tr>
                        <td>{{ log.username }}</td>
                        <td>{{ log.ip_address }}</td>
                        <td>{{ log.timestamp }}</td>
                        <td>{{ log.action }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            <p class="text-center mt-3"><a href="/mrhjf" class="btn btn-secondary">Back to Admin Panel</a></p>
        </div>
    </div>
</body>
</html>
'''

REAL_TIME_LOGS_PAGE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Real-Time Logs</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container d-flex justify-content-center align-items-center min-vh-100">
        <div class="card p-4 shadow-sm" style="width: 100%; max-width: 1200px;">
            <h3 class="text-center mb-3">Real-Time Logs</h3>
            <div id="logs" class="mt-3">
                <!-- Logs will be displayed here -->
            </div>
            <p class="text-center mt-3"><a href="/mrhjf" class="btn btn-secondary">Back to Admin Panel</a></p>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        const logsDiv = document.getElementById('logs');
        const eventSource = new EventSource('/mrhjf/real_time_logs_stream');
        eventSource.onmessage = function(event) {
            const log = JSON.parse(event.data);
            const logElement = document.createElement('div');
            logElement.textContent = `${log.timestamp} - ${log.username} - ${log.ip_address} - ${log.action}`;
            logsDiv.appendChild(logElement);
        };
    </script>
</body>
</html>
'''

CHAT_LOGS_PAGE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Chat Logs</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container d-flex justify-content-center align-items-center min-vh-100">
        <div class="card p-4 shadow-sm" style="width: 100%; max-width: 1200px;">
            <h3 class="text-center mb-3">Chat Logs</h3>
            <table class="table">
                <thead>
                    <tr>
                        <th>Sender</th>
                        <th>Recipient</th>
                        <th>Message</th>
                        <th>Timestamp</th>
                    </tr>
                </thead>
                <tbody>
                    {% for message in chat_messages %}
                    <tr>
                        <td>{{ message.sender }}</td>
                        <td>{{ message.recipient }}</td>
                        <td>{{ message.message }}</td>
                        <td>{{ message.timestamp }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            <p class="text-center mt-3"><a href="/mrhjf" class="btn btn-secondary">Back to Admin Panel</a></p>
        </div>
    </div>
</body>
</html>
'''

REAL_TIME_CHAT_PAGE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Real-Time Chat</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            background-color: #1e1e1e;
            color: #ffffff;
            font-family: 'Arial', sans-serif;
        }
        .chat-box {
            height: 400px;
            overflow-y: scroll;
            border: 1px solid #444;
            padding: 10px;
            margin-bottom: 10px;
            background-color: #2d2d2d;
            border-radius: 5px;
        }
        .message {
            padding: 8px;
            margin-bottom: 10px;
            border-radius: 5px;
            background-color: #3a3a3a;
        }
        .message strong {
            color: #4caf50;
        }
        .message em {
            color: #888;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container d-flex justify-content-center align-items-center min-vh-100">
        <div class="card p-4 shadow-sm" style="width: 100%; max-width: 1200px; background-color: #2d2d2d;">
            <h3 class="text-center mb-3">Real-Time Chat</h3>
            <div id="chat-box" class="chat-box">
                <!-- Chat messages will appear here -->
            </div>
            <p class="text-center mt-3"><a href="/mrhjf" class="btn btn-secondary">Back to Admin Panel</a></p>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <script>
        const socket = io();
        const chatBox = document.getElementById('chat-box');

        // Receive messages
        socket.on('receive_message', function(data) {
            const messageElement = document.createElement('div');
            messageElement.className = 'message';
            messageElement.innerHTML = `<strong>${data.sender}</strong> to <strong>${data.recipient}</strong>: ${data.message} <em>(${data.timestamp})</em>`;
            chatBox.appendChild(messageElement);
            chatBox.scrollTop = chatBox.scrollHeight;
        });
    </script>
</body>
</html>
'''

RECOVERY_REQUESTS_PAGE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Recovery Requests</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container d-flex justify-content-center align-items-center min-vh-100">
        <div class="card p-4 shadow-sm" style="width: 100%; max-width: 1200px;">
            <h3 class="text-center mb-3">Recovery Requests</h3>
            <table class="table">
                <thead>
                    <tr>
                        <th>Username</th>
                        <th>Telegram ID</th>
                        <th>Timestamp</th>
                    </tr>
                </thead>
                <tbody>
                    {% for request in recovery_requests %}
                    <tr>
                        <td>{{ request.username }}</td>
                        <td>{{ request.telegram_id }}</td>
                        <td>{{ request.timestamp }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            <p class="text-center mt-3"><a href="/mrhjf" class="btn btn-secondary">Back to Admin Panel</a></p>
        </div>
    </div>
</body>
</html>
'''

if __name__ == '__main__':
    # Create admin user if not exists
    data = load_data()
    if not any(u['username'] == 'Alireza_jf' for u in data['users']):
        admin_user = {
            'username': 'Alireza_jf',
            'password': hash_password('mrhjf5780'),  # رمز عبور پیش‌فرض
            'telegram_id': 'admin_telegram_id',  # آیدی تلگرام مدیر
            'role': 'admin',
            'max_attempts': 3
        }
        data['users'].append(admin_user)
        save_data(data)
        print("Admin user created with username: Alireza_jf and password: mrhjf5780")

    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
