from flask import Flask, render_template_string, request, redirect, flash, session
import os
import time
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# مسیر فایل برای ذخیره‌ی کاربران
USER_DATA_FILE = 'users.txt'

# دیکشنری برای ذخیره تعداد دفعات تلاش ناموفق و زمان مسدودی
failed_attempts = {}
blocked_users = {}

def load_users():
    """بارگذاری کاربران از فایل"""
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

def save_user(username, password, max_attempts=3):
    """ذخیره یک کاربر جدید در فایل"""
    with open(USER_DATA_FILE, 'a') as file:
        file.write(f'{username},{password},{max_attempts}\n')

def update_user(users):
    """به‌روزرسانی فایل کاربران"""
    with open(USER_DATA_FILE, 'w') as file:
        for user in users:
            file.write(f'{user[0]},{user[1]},{user[2]}\n')

@app.route('/')
def login():
    """صفحه ورود"""
    return render_template_string(LOGIN_PAGE)

@app.route('/login', methods=['POST'])
def do_login():
    """عملیات ورود"""
    username = request.form['username']
    password = request.form['password']
    
    # بررسی مسدودی کاربر
    if username in blocked_users:
        if datetime.now() < blocked_users[username]:
            remaining_time = (blocked_users[username] - datetime.now()).seconds
            flash(f'You are blocked for {remaining_time} seconds. Please try again later.', 'purple')
            return redirect('/')
        else:
            del blocked_users[username]
            failed_attempts[username] = 0
    
    users = load_users()
    for user in users:
        if user[0] == username and user[1] == password:
            if username == 'Alireza_jf' and password == 'Mrhjf5780':
                session['admin'] = True
                return redirect('/admin')
            else:
                session['username'] = username
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
        blocked_users[username] = datetime.now() + timedelta(minutes=1)
        flash(f'You have been blocked for 1 minute due to too many failed attempts.', 'purple')
    else:
        flash('Invalid username or password', 'danger')
    
    return redirect('/')

@app.route('/success')
def success():
    """صفحه موفقیت‌آمیز ورود"""
    if 'username' not in session:
        return redirect('/')
    
    ip_address = request.remote_addr
    desktop_path = os.path.join(os.path.expanduser('~'), 'Desktop')
    files = os.listdir(desktop_path)
    
    return render_template_string(SUCCESS_PAGE, ip_address=ip_address, files=files)

@app.route('/logout')
def logout():
    """خروج از سیستم"""
    session.pop('username', None)
    session.pop('admin', None)
    return redirect('/')

@app.route('/admin')
def admin():
    """صفحه ادمین"""
    if not session.get('admin'):
        return redirect('/')
    
    users = load_users()
    return render_template_string(ADMIN_PAGE, users=users)

@app.route('/admin/update', methods=['POST'])
def admin_update():
    """به‌روزرسانی کاربران توسط ادمین"""
    if not session.get('admin'):
        return redirect('/')
    
    username = request.form.get('username')
    password = request.form.get('password')
    max_attempts = request.form.get('max_attempts')
    action = request.form.get('action')
    
    users = load_users()
    if action == 'add':
        users.append([username, password, max_attempts or 3])
    elif action == 'delete':
        users = [user for user in users if user[0] != username]
    elif action == 'update':
        for user in users:
            if user[0] == username:
                if password:
                    user[1] = password
                if max_attempts:
                    user[2] = max_attempts
    
    update_user(users)
    return redirect('/admin')

@app.route('/signup')
def signup():
    """صفحه ثبت‌نام"""
    return render_template_string(SIGNUP_PAGE)

@app.route('/signup', methods=['POST'])
def do_signup():
    """عملیات ثبت‌نام"""
    username = request.form['username']
    password = request.form['password']
    
    users = load_users()
    for user in users:
        if user[0] == username:
            flash('Username already exists!', 'danger')
            return redirect('/signup')

    save_user(username, password)
    flash('Account created successfully! Please log in.', 'success')
    return redirect('/')

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
                            <form action="/admin/update" method="POST" style="display:inline;">
                                <input type="hidden" name="username" value="{{ user[0] }}">
                                <input type="text" name="password" placeholder="New Password">
                                <input type="number" name="max_attempts" placeholder="Max Attempts">
                                <input type="hidden" name="action" value="update">
                                <button type="submit" class="btn btn-warning btn-sm">Update</button>
                            </form>
                            <form action="/admin/update" method="POST" style="display:inline;">
                                <input type="hidden" name="username" value="{{ user[0] }}">
                                <input type="hidden" name="action" value="delete">
                                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
                            </form>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            <form action="/admin/update" method="POST">
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
            <p class="text-center mt-3"><a href="/logout" class="btn btn-secondary">Logout</a></p>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
'''

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
