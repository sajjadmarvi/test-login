from flask import Flask, render_template_string, request, redirect, flash, session, jsonify
from markupsafe import Markup
import os
import time
from datetime import datetime, timedelta, timezone
import json
import bcrypt
import pyotp
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_mail import Mail, Message
import smtplib
from flask_babel import Babel, gettext
from flask_recaptcha import ReCaptcha
import sqlite3
import pytest
from threading import Thread
import shutil

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'sajjadbul202@gmail.com'
app.config['MAIL_PASSWORD'] = 'your_email_password'
app.config['RECAPTCHA_SITE_KEY'] = 'your_recaptcha_site_key'
app.config['RECAPTCHA_SECRET_KEY'] = 'your_recaptcha_secret_key'
app.config['BABEL_DEFAULT_LOCALE'] = 'en'

mail = Mail(app)
recaptcha = ReCaptcha(app)
babel = Babel(app)
limiter = Limiter(app)

# مسیر فایل برای ذخیره‌ی کاربران و لاگ‌ها
USER_DATA_FILE = 'users.txt'
LOG_FILE = 'logs.json'
BACKUP_DIR = 'backup'

# بررسی و ایجاد فایل‌ها و پوشه‌های مورد نیاز
if not os.path.exists(USER_DATA_FILE):
    with open(USER_DATA_FILE, 'w') as file:
        file.write('')  # ایجاد یک فایل خالی

if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, 'w') as file:
        json.dump([], file)  # ایجاد یک فایل خالی با فرمت JSON

if not os.path.exists(BACKUP_DIR):
    os.makedirs(BACKUP_DIR)

# دیکشنری برای ذخیره تعداد دفعات تلاش ناموفق و زمان مسدودی
failed_attempts = {}
blocked_users = {}

# تابع برای هش کردن رمز عبور
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

# تابع برای بررسی رمز عبور
def check_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

# تابع برای تولید کد OTP
def generate_otp():
    return pyotp.TOTP(pyotp.random_base32()).now()

# تابع برای ارسال ایمیل
def send_email(to, subject, body):
    msg = Message(subject, sender='sajjadbul202@gmail.com', recipients=[to])
    msg.body = body
    mail.send(msg)

# تابع برای ارسال پیامک
def send_sms(to, message):
    # این تابع نیاز به تنظیمات API پیامک دارد
    pass

# تابع برای پشتیبان‌گیری از فایل‌ها
def backup_files():
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)
    shutil.copy(USER_DATA_FILE, os.path.join(BACKUP_DIR, 'users_backup.txt'))
    shutil.copy(LOG_FILE, os.path.join(BACKUP_DIR, 'logs_backup.json'))

# تابع برای بارگذاری کاربران از فایل
def load_users():
    if not os.path.exists(USER_DATA_FILE):
        return []
    users = []
    with open(USER_DATA_FILE, 'r') as file:
        for line in file.readlines():
            parts = line.strip().split(',')
            if len(parts) == 2:  # اگر max_attempts وجود نداشت
                parts.append('3')  # مقدار پیش‌فرض ۳
            users.append(parts)
    return users

# تابع برای ذخیره یک کاربر جدید در فایل
def save_user(username, password, max_attempts=3):
    with open(USER_DATA_FILE, 'a') as file:
        file.write(f'{username},{password},{max_attempts}\n')

# تابع برای به‌روزرسانی فایل کاربران
def update_user(users):
    with open(USER_DATA_FILE, 'w') as file:
        for user in users:
            file.write(f'{user[0]},{user[1]},{user[2]}\n')

# تابع برای ذخیره فعالیت‌های کاربر در فایل لاگ
def log_activity(username, ip_address, user_agent, attempted_credentials, duration=None):
    log_entry = {
        'timestamp': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
        'username': username,
        'ip_address': ip_address,
        'user_agent': user_agent,
        'attempted_credentials': attempted_credentials,
        'duration': duration
    }
    
    logs = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'r') as file:
            logs = json.load(file)
    
    logs.append(log_entry)
    
    with open(LOG_FILE, 'w') as file:
        json.dump(logs, file, indent=4)

# صفحه ورود
@app.route('/')
def login():
    return render_template_string(LOGIN_PAGE)

# عملیات ورود
@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def do_login():
    username = request.form['username']
    password = request.form['password']
    ip_address = request.remote_addr
    user_agent = request.headers.get('User-Agent')
    attempted_credentials = f"{username}/{password}"
    
    # بررسی مسدودی کاربر
    if username in blocked_users:
        if datetime.now(timezone.utc) < blocked_users[username]:
            remaining_time = (blocked_users[username] - datetime.now(timezone.utc)).seconds
            flash(f'You are blocked for {remaining_time} seconds. Please try again later.', 'purple')
            return redirect('/')
        else:
            del blocked_users[username]
            failed_attempts[username] = 0
    
    users = load_users()
    for user in users:
        if user[0] == username and check_password(password, user[1]):
            if username == 'Alireza_jf' and password == 'Mrhjf5780':
                session['admin'] = True
                log_activity(username, ip_address, user_agent, attempted_credentials)
                return redirect('/mrhjf')
            else:
                session['username'] = username
                session['login_time'] = datetime.now(timezone.utc)
                flash('Login successful!', 'success')
                time.sleep(2)
                return redirect('/success')
    
    # افزایش تعداد تلاش‌های ناموفق
    if username in failed_attempts:
        failed_attempts[username] += 1
    else:
        failed_attempts[username] = 1
    
    # پیدا کردن کاربر و بررسی max_attempts
    max_attempts = 3  # مقدار پیش‌فرض
    for user in users:
        if user[0] == username:
            max_attempts = int(user[2]) if len(user) > 2 else 3  # اگر max_attempts وجود نداشت، پیش‌فرض ۳
            break
    
    if failed_attempts[username] >= max_attempts:
        blocked_users[username] = datetime.now(timezone.utc) + timedelta(minutes=1)
        flash(f'You have been blocked for 1 minute due to too many failed attempts.', 'purple')
    else:
        flash('Invalid username or password', 'danger')
    
    log_activity(username, ip_address, user_agent, attempted_credentials)
    return redirect('/')

# صفحه موفقیت‌آمیز ورود
@app.route('/success')
def success():
    if 'username' not in session:
        return redirect('/')
    
    username = session['username']
    ip_address = request.remote_addr
    user_agent = request.headers.get('User-Agent')
    login_time = session.get('login_time')
    
    if login_time:
        if login_time.tzinfo is not None and login_time.tzinfo.utcoffset(login_time) is not None:
            login_time = login_time.replace(tzinfo=None)
        duration = (datetime.now() - login_time).seconds // 60
    else:
        duration = None
    
    log_activity(username, ip_address, user_agent, "Successful Login", duration)
    
    desktop_path = os.path.join(os.path.expanduser('~'), 'Desktop')
    files = os.listdir(desktop_path)
    
    return render_template_string(SUCCESS_PAGE, ip_address=ip_address, files=files)

# خروج از سیستم
@app.route('/logout')
def logout():
    username = session.get('username')
    ip_address = request.remote_addr
    user_agent = request.headers.get('User-Agent')
    login_time = session.get('login_time')
    
    if login_time:
        if login_time.tzinfo is not None and login_time.tzinfo.utcoffset(login_time) is not None:
            login_time = login_time.replace(tzinfo=None)
        duration = (datetime.now() - login_time).seconds // 60
    else:
        duration = None
    
    log_activity(username, ip_address, user_agent, "Logged Out", duration)
    
    session.pop('username', None)
    session.pop('admin', None)
    session.pop('login_time', None)
    return redirect('/')

# صفحه مدیر
@app.route('/mrhjf')
def mrhjf():
    if not session.get('admin'):
        return redirect('/')
    
    users = load_users()
    return render_template_string(ADMIN_PAGE, users=users)

# صفحه لاگ‌ها برای مدیر
@app.route('/mrhjf/logs')
def mrhjf_logs():
    if not session.get('admin'):
        return redirect('/')
    
    if not os.path.exists(LOG_FILE):
        logs = []
    else:
        with open(LOG_FILE, 'r') as file:
            logs = json.load(file)
    
    # سازمان‌دهی لاگ‌ها بر اساس IP
    ip_logs = {}
    for log in logs:
        ip = log['ip_address']
        if ip not in ip_logs:
            ip_logs[ip] = []
        ip_logs[ip].append(log)
    
    return render_template_string(LOGS_PAGE, ip_logs=ip_logs)

# به‌روزرسانی کاربران توسط مدیر
@app.route('/mrhjf/update', methods=['POST'])
def mrhjf_update():
    if not session.get('admin'):
        return redirect('/')
    
    username = request.form.get('username')
    password = request.form.get('password')
    max_attempts = request.form.get('max_attempts')
    action = request.form.get('action')
    
    users = load_users()
    if action == 'add':
        users.append([username, hash_password(password).decode('utf-8'), max_attempts or 3])
    elif action == 'delete':
        users = [user for user in users if user[0] != username]
    elif action == 'update':
        for user in users:
            if user[0] == username:
                if password:
                    user[1] = hash_password(password).decode('utf-8')
                if max_attempts:
                    user[2] = max_attempts
    
    update_user(users)
    return redirect('/mrhjf')

# صفحه ثبت‌نام
@app.route('/signup')
def signup():
    return render_template_string(SIGNUP_PAGE)

# عملیات ثبت‌نام
@app.route('/signup', methods=['POST'])
def do_signup():
    username = request.form['username']
    password = request.form['password']
    
    users = load_users()
    for user in users:
        if user[0] == username:
            flash('Username already exists!', 'danger')
            return redirect('/signup')

    save_user(username, hash_password(password).decode('utf-8'))
    flash('Account created successfully! Please log in.', 'success')
    return redirect('/')

# صفحه بازیابی رمز عبور
@app.route('/forgot_password')
def forgot_password():
    return render_template_string(FORGOT_PASSWORD_PAGE)

# عملیات بازیابی رمز عبور
@app.route('/forgot_password', methods=['POST'])
def do_forgot_password():
    username = request.form['username']
    users = load_users()
    for user in users:
        if user[0] == username:
            otp = generate_otp()
            send_email('sajjadbul202@gmail.com', 'Password Recovery OTP', f'Your OTP is: {otp}')
            flash('An OTP has been sent to your email.', 'success')
            return redirect('/reset_password')
    flash('Username not found!', 'danger')
    return redirect('/forgot_password')

# صفحه بازنشانی رمز عبور
@app.route('/reset_password')
def reset_password():
    return render_template_string(RESET_PASSWORD_PAGE)

# عملیات بازنشانی رمز عبور
@app.route('/reset_password', methods=['POST'])
def do_reset_password():
    username = request.form['username']
    otp = request.form['otp']
    new_password = request.form['new_password']
    
    users = load_users()
    for user in users:
        if user[0] == username:
            if otp == generate_otp():
                user[1] = hash_password(new_password).decode('utf-8')
                update_user(users)
                flash('Password reset successfully!', 'success')
                return redirect('/')
            else:
                flash('Invalid OTP!', 'danger')
                return redirect('/reset_password')
    flash('Username not found!', 'danger')
    return redirect('/reset_password')

# صفحه گزارش‌های تحلیلی
@app.route('/mrhjf/reports')
def mrhjf_reports():
    if not session.get('admin'):
        return redirect('/')
    
    logs = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'r') as file:
            logs = json.load(file)
    
    # تحلیل داده‌ها
    total_logins = len(logs)
    failed_logins = len([log for log in logs if log['attempted_credentials'] != "Successful Login"])
    unique_ips = len(set(log['ip_address'] for log in logs))
    
    return render_template_string(REPORTS_PAGE, total_logins=total_logins, failed_logins=failed_logins, unique_ips=unique_ips)

# صفحه دسترسی‌های سطحی
@app.route('/mrhjf/access_control')
def mrhjf_access_control():
    if not session.get('admin'):
        return redirect('/')
    
    users = load_users()
    return render_template_string(ACCESS_CONTROL_PAGE, users=users)

# عملیات به‌روزرسانی دسترسی‌ها
@app.route('/mrhjf/update_access', methods=['POST'])
def mrhjf_update_access():
    if not session.get('admin'):
        return redirect('/')
    
    username = request.form.get('username')
    role = request.form.get('role')
    
    users = load_users()
    for user in users:
        if user[0] == username:
            user.append(role)
            break
    
    update_user(users)
    return redirect('/mrhjf/access_control')

# صفحه جستجو و فیلتر لاگ‌ها
@app.route('/mrhjf/search_logs')
def mrhjf_search_logs():
    if not session.get('admin'):
        return redirect('/')
    
    query = request.args.get('query', '')
    logs = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'r') as file:
            logs = json.load(file)
    
    filtered_logs = [log for log in logs if query.lower() in log['username'].lower() or query.lower() in log['ip_address'].lower()]
    
    return render_template_string(SEARCH_LOGS_PAGE, logs=filtered_logs, query=query)

# صفحه لاگ‌گیری Real-Time
@app.route('/mrhjf/real_time_logs')
def mrhjf_real_time_logs():
    if not session.get('admin'):
        return redirect('/')
    
    return render_template_string(REAL_TIME_LOGS_PAGE)

# تابع برای پشتیبان‌گیری دوره‌ای
def periodic_backup():
    while True:
        backup_files()
        time.sleep(3600)  # هر ساعت یک بار پشتیبان‌گیری

# شروع پشتیبان‌گیری دوره‌ای در یک thread جداگانه
backup_thread = Thread(target=periodic_backup)
backup_thread.daemon = True
backup_thread.start()

# کدهای HTML و CSS
LOGIN_PAGE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Instagram Login</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            background-color: #fafafa;
            font-family: Arial, sans-serif;
        }
        .card {
            border-radius: 8px;
        }
        h3 {
            font-family: 'Billabong', cursive;
            font-size: 2rem;
            color: #262626;
        }
        .alert-purple {
            background-color: #6f42c1;
            color: white;
        }
    </style>
</head>
<body>
    <div class="container d-flex justify-content-center align-items-center min-vh-100">
        <div class="card p-4 shadow-sm" style="width: 100%; max-width: 350px;">
            <h3 class="text-center mb-3">Instagram</h3>
            {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
            <div class="alert alert-{{ messages[0][0] }} alert-dismissible fade show" role="alert">
                {{ messages[0][1] }}
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            </div>
            {% endif %}
            {% endwith %}
            <form action="/login" method="POST">
                <div class="mb-3">
                    <input type="text" name="username" class="form-control" placeholder="Username" required>
                </div>
                <div class="mb-3">
                    <input type="password" name="password" class="form-control" placeholder="Password" required>
                </div>
                <button type="submit" class="btn btn-primary w-100">Log In</button>
            </form>
            <p class="text-center mt-3">Don't have an account? <a href="/signup">Sign up</a></p>
            <p class="text-center mt-3"><a href="/forgot_password">Forgot Password?</a></p>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
'''

SIGNUP_PAGE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Instagram Sign Up</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            background-color: #fafafa;
            font-family: Arial, sans-serif;
        }
        .card {
            border-radius: 8px;
        }
        h3 {
            font-family: 'Billabong', cursive;
            font-size: 2rem;
            color: #262626;
        }
    </style>
</head>
<body>
    <div class="container d-flex justify-content-center align-items-center min-vh-100">
        <div class="card p-4 shadow-sm" style="width: 100%; max-width: 350px;">
            <h3 class="text-center mb-3">Instagram</h3>
            {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
            <div class="alert alert-{{ messages[0][0] }} alert-dismissible fade show" role="alert">
                {{ messages[0][1] }}
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            </div>
            {% endif %}
            {% endwith %}
            <form action="/signup" method="POST">
                <div class="mb-3">
                    <input type="text" name="username" class="form-control" placeholder="Choose a Username" required>
                </div>
                <div class="mb-3">
                    <input type="password" name="password" class="form-control" placeholder="Choose a Password" required>
                </div>
                <button type="submit" class="btn btn-primary w-100">Sign Up</button>
            </form>
            <p class="text-center mt-3">Already have an account? <a href="/">Log in</a></p>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
'''

SUCCESS_PAGE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login Successful</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            background-color: #fafafa;
            font-family: Arial, sans-serif;
        }
        .card {
            border-radius: 8px;
        }
        h3 {
            font-family: 'Billabong', cursive;
            font-size: 2rem;
            color: #262626;
        }
    </style>
</head>
<body>
    <div class="container d-flex justify-content-center align-items-center min-vh-100">
        <div class="card p-4 shadow-sm" style="width: 100%; max-width: 350px;">
            <h3 class="text-center mb-3">Login Successful</h3>
            <p>Your login has been verified. You have accessed this page either by cracking, penetration testing, or by creating a new account.</p>
            <p>Your public IP address is: {{ ip_address }}</p>
            <p>Files on your system desktop:</p>
            <ul>
                {% for file in files %}
                <li>{{ file }}</li>
                {% endfor %}
            </ul>
            <p>You must log in with an admin account to prevent these files from being leaked.</p>
            <div class="d-flex justify-content-between">
                <a href="/" class="btn btn-success">Back to Login</a>
                <button class="btn btn-danger" onclick="window.close()">Exit</button>
            </div>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
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
    <style>
        body {
            background-color: #fafafa;
            font-family: Arial, sans-serif;
        }
        .card {
            border-radius: 8px;
        }
        h3 {
            font-family: 'Billabong', cursive;
            font-size: 2rem;
            color: #262626;
        }
    </style>
</head>
<body>
    <div class="container d-flex justify-content-center align-items-center min-vh-100">
        <div class="card p-4 shadow-sm" style="width: 100%; max-width: 800px;">
            <h3 class="text-center mb-3">Admin Panel</h3>
            <table class="table">
                <thead>
                    <tr>
                        <th>Username</th>
                        <th>Password</th>
                        <th>Max Attempts</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {% for user in users %}
                    <tr>
                        <td>{{ user[0] }}</td>
                        <td>{{ user[1] }}</td>
                        <td>{{ user[2] }}</td>
                        <td>
                            <form action="/mrhjf/update" method="POST" style="display:inline;">
                                <input type="hidden" name="username" value="{{ user[0] }}">
                                <input type="text" name="password" placeholder="New Password">
                                <input type="number" name="max_attempts" placeholder="Max Attempts">
                                <input type="hidden" name="action" value="update">
                                <button type="submit" class="btn btn-warning btn-sm">Update</button>
                            </form>
                            <form action="/mrhjf/update" method="POST" style="display:inline;">
                                <input type="hidden" name="username" value="{{ user[0] }}">
                                <input type="hidden" name="action" value="delete">
                                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
                            </form>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            <form action="/mrhjf/update" method="POST">
                <div class="mb-3">
                    <input type="text" name="username" class="form-control" placeholder="New Username" required>
                </div>
                <div class="mb-3">
                    <input type="password" name="password" class="form-control" placeholder="New Password" required>
                </div>
                <div class="mb-3">
                    <input type="number" name="max_attempts" class="form-control" placeholder="Max Attempts" required>
                </div>
                <input type="hidden" name="action" value="add">
                <button type="submit" class="btn btn-primary w-100">Add User</button>
            </form>
            <p class="text-center mt-3"><a href="/mrhjf/logs" class="btn btn-info">View Logs</a></p>
            <p class="text-center mt-3"><a href="/logout" class="btn btn-secondary">Logout</a></p>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
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
    <style>
        body {
            background-color: #fafafa;
            font-family: Arial, sans-serif;
        }
        .card {
            border-radius: 8px;
        }
        h3 {
            font-family: 'Billabong', cursive;
            font-size: 2rem;
            color: #262626;
        }
        .details {
            display: none;
            margin-left: 20px;
        }
    </style>
    <script>
        function toggleDetails(id) {
            var element = document.getElementById(id);
            if (element.style.display === "none") {
                element.style.display = "block";
            } else {
                element.style.display = "none";
            }
        }
    </script>
</head>
<body>
    <div class="container d-flex justify-content-center align-items-center min-vh-100">
        <div class="card p-4 shadow-sm" style="width: 100%; max-width: 1200px;">
            <h3 class="text-center mb-3">Admin Logs</h3>
            <table class="table">
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {% for ip, logs in ip_logs.items() %}
                    <tr>
                        <td>{{ ip }}</td>
                        <td>
                            <button class="btn btn-info btn-sm" onclick="toggleDetails('system_{{ loop.index }}')">System Info</button>
                            <button class="btn btn-warning btn-sm" onclick="toggleDetails('duration_{{ loop.index }}')">Duration</button>
                            <button class="btn btn-danger btn-sm" onclick="toggleDetails('attempts_{{ loop.index }}')">Attempts</button>
                        </td>
                    </tr>
                    <tr>
                        <td colspan="2">
                            <div id="system_{{ loop.index }}" class="details">
                                <h5>System Info:</h5>
                                <ul>
                                    {% for log in logs %}
                                    <li>{{ log.user_agent }}</li>
                                    {% endfor %}
                                </ul>
                            </div>
                            <div id="duration_{{ loop.index }}" class="details">
                                <h5>Duration:</h5>
                                <ul>
                                    {% for log in logs %}
                                    <li>{{ log.duration }} minutes</li>
                                    {% endfor %}
                                </ul>
                            </div>
                            <div id="attempts_{{ loop.index }}" class="details">
                                <h5>Attempts:</h5>
                                <ul>
                                    {% for log in logs %}
                                    <li>{{ log.attempted_credentials }}</li>
                                    {% endfor %}
                                </ul>
                            </div>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            <p class="text-center mt-3"><a href="/mrhjf" class="btn btn-secondary">Back to Admin Panel</a></p>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
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
    <style>
        body {
            background-color: #fafafa;
            font-family: Arial, sans-serif;
        }
        .card {
            border-radius: 8px;
        }
        h3 {
            font-family: 'Billabong', cursive;
            font-size: 2rem;
            color: #262626;
        }
    </style>
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
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
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
    <style>
        body {
            background-color: #fafafa;
            font-family: Arial, sans-serif;
        }
        .card {
            border-radius: 8px;
        }
        h3 {
            font-family: 'Billabong', cursive;
            font-size: 2rem;
            color: #262626;
        }
    </style>
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
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {% for user in users %}
                    <tr>
                        <td>{{ user[0] }}</td>
                        <td>{{ user[3] if user|length > 3 else 'User' }}</td>
                        <td>
                            <form action="/mrhjf/update_access" method="POST" style="display:inline;">
                                <input type="hidden" name="username" value="{{ user[0] }}">
                                <select name="role" class="form-select">
                                    <option value="User">User</option>
                                    <option value="Admin">Admin</option>
                                </select>
                                <button type="submit" class="btn btn-warning btn-sm">Update Role</button>
                            </form>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            <p class="text-center mt-3"><a href="/mrhjf" class="btn btn-secondary">Back to Admin Panel</a></p>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
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
    <style>
        body {
            background-color: #fafafa;
            font-family: Arial, sans-serif;
        }
        .card {
            border-radius: 8px;
        }
        h3 {
            font-family: 'Billabong', cursive;
            font-size: 2rem;
            color: #262626;
        }
    </style>
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
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
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
    <style>
        body {
            background-color: #fafafa;
            font-family: Arial, sans-serif;
        }
        .card {
            border-radius: 8px;
        }
        h3 {
            font-family: 'Billabong', cursive;
            font-size: 2rem;
            color: #262626;
        }
    </style>
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
    app.run(debug=True, host='0.0.0.0', port=5000)
