from flask import Flask, render_template_string, request, redirect, flash, session, jsonify
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
from config import Config, DevelopmentConfig, ProductionConfig  # وارد کردن کلاس‌های تنظیمات
from datetime import datetime

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
            # اگر فایل خراب است، یک فایل جدید ایجاد کنید
            print("Corrupted data.json file. Creating a new one.")
            default_data = {'users': []}
            save_data(default_data)
            return default_data
    return {'users': []}

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
        flash('Login successful!', 'success')
        if user['role'] == 'admin':
            return redirect('/mrhjf')
        return redirect('/success')
    else:
        flash('Invalid username or password', 'danger')
    return redirect('/')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect('/signup')
        
        data = load_data()
        if any(u['username'] == username for u in data['users']):
            flash('Username already exists!', 'danger')
            return redirect('/signup')
        
        # Create new user
        new_user = {
            'username': username,
            'password': hash_password(password),
            'role': 'user',
            'max_attempts': 3
        }
        data['users'].append(new_user)
        save_data(data)  # ذخیره کاربر جدید در فایل JSON
        
        flash('Account created successfully! Please log in.', 'success')
        return redirect('/')
    return render_template_string(SIGNUP_PAGE)

@app.route('/success')
def success():
    if 'username' not in session:
        return redirect('/')
    return render_template_string(SUCCESS_PAGE, ip_address=request.remote_addr)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

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
    failed_logins = len([log for log in logs if log['attempted_credentials'] != "Successful Login"])
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
    flash(f'Backup created successfully: {backup_filename}', 'success')
    return redirect('/mrhjf')

# WebSocket
@socketio.on('connect')
def handle_connect():
    emit('log', {'data': 'Connected'})

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
                <button type="submit" class="btn btn-primary w-100">Sign Up</button>
            </form>
            <p class="text-center mt-3">Already have an account? <a href="/">Log in</a></p>
        </div>
    </div>
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
                    </tr>
                </thead>
                <tbody>
                    {% for log in logs %}
                    <tr>
                        <td>{{ log.username }}</td>
                        <td>{{ log.ip_address }}</td>
                        <td>{{ log.timestamp }}</td>
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
                    </tr>
                </thead>
                <tbody>
                    {% for log in logs %}
                    <tr>
                        <td>{{ log.username }}</td>
                        <td>{{ log.ip_address }}</td>
                        <td>{{ log.timestamp }}</td>
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
            logElement.textContent = `${log.timestamp} - ${log.username} - ${log.ip_address}`;
            logsDiv.appendChild(logElement);
        };
    </script>
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
            'role': 'admin',
            'max_attempts': 3
        }
        data['users'].append(admin_user)
        save_data(data)
        print("Admin user created with username: Alireza_jf and password: mrhjf5780")

    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
