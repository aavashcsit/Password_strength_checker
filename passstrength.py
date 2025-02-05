import re
import hashlib
import requests

# Function to check password strength
def check_password_strength(password):
    strength_score = 0
    
    # Criteria for password strength
    if len(password) >= 8:
        strength_score += 1
    if re.search(r'[A-Z]', password):
        strength_score += 1
    if re.search(r'[a-z]', password):
        strength_score += 1
    if re.search(r'\d', password):
        strength_score += 1
    if re.search(r'[@$!%*?&]', password):
        strength_score += 1
    
    # Display strength rating
    strength_levels = {
        1: "Very Weak",
        2: "Weak",
        3: "Moderate",
        4: "Strong",
        5: "Very Strong"
    }
    
    return strength_levels.get(strength_score, "Very Weak")

# Function to check if password has been leaked
def check_password_breach(password):
    # Hash the password using SHA-1
    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]

    # Use "Have I Been Pwned" API to check for leaks
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)

    if suffix in response.text:
        return "⚠️ This password has been leaked! Choose a different one."
    else:
        return "✅ This password is safe."

# Main function
if __name__ == "__main__":
    password = input("Enter your password: ")
    
    # Check strength
    strength = check_password_strength(password)
    print(f"Password Strength: {strength}")
    
    # Check if password is breached
    breach_status = check_password_breach(password)
    print(breach_status)
