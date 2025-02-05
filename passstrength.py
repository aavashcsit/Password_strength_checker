import re
import hashlib
import requests

def check_password_strength(password):
    strength_score = 0

    if len(password) >= 8:
        strength_score += 1
    if re.search(r'[A-Z]',password):
        strength_score += 1
    if re.search(r'[a-z]',password):
        strength_score += 1
    if re.search(r'[\d]',password):
        strength_score += 1
    if re.search(r'[punctuation]',password):
        strength_score += 1

    strength_levels = {
        1: "Very Weak",
        2: "Weak",
        3: "Moderate",
        4: "Strong",
        5: "Very Strong"
    }

    return strength_levels.get(strength_score,"Try another one")

def check_password_breach(password):

    sha1_hashfunction = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix,suffix = sha1_hashfunction[:5],sha1_hashfunction[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)
    
    if suffix in response.text:
        return "This password has been compromised! Try new one."
    else:
        return "This is a secure password."
    
if __name__ == "__main__":
    password = input("Enter your password: ")
    
    strength = check_password_strength(password)
    print(f"Password Strength: {strength}")
    
    breach_status = check_password_breach(password)
    print(breach_status)

