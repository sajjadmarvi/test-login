from flask import Flask, render_template_string, request, redirect, flash
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# مسیر فایل برای ذخیره‌ی کاربران
USER_DATA_FILE = 'users.txt'


def load_users():
    """بارگذاری کاربران از فایل"""
    if not os.path.exists(USER_DATA_FILE):
        return []
    with open(USER_DATA_FILE, 'r') as file:
        users = [line.strip().split(',') for line in file.readlines()]
    return users


def save_user(username, password):
    """ذخیره یک کاربر جدید در فایل"""
    with open(USER_DATA_FILE, 'a') as file:
        file.write(f'{username},{password}\n')


@app.route('/')
def login():
    """صفحه ورود"""
    return render_template_string(LOGIN_PAGE)


@app.route('/login', methods=['POST'])
def do_login():
    """عملیات ورود"""
    username = request.form['username']
    password = request.form['password']
    
    users = load_users()
    for user in users:
        if user[0] == username and user[1] == password:
            flash('Login successful!', 'success')
            return redirect('/')
    
    flash('Invalid username or password', 'danger')
    return redirect('/')


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
    </style>
</head>
<body>
    <div class="container d-flex justify-content-center align-items-center min-vh-100">
        <div class="card p-4 shadow-sm" style="width: 100%; max-width: 350px;">
            <h3 class="text-center mb-3">Instagram</h3>
            {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
            <div class="alert {{ messages[0][0] }} alert-dismissible fade show" role="alert">
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
            <div class="alert {{ messages[0][0] }} alert-dismissible fade show" role="alert">
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

if __name__ == '__main__':
    app.run(debug=True)
