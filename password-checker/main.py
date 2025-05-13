import math
import re
import random
import string
import argparse
from pathlib import Path
import hashlib
import requests
import zxcvbn

def load_password_list(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            return set(line.strip().lower() for line in file if line.strip())
    except FileNotFoundError:
        print(f"Warning: {file_path} not found. Using empty list.")
        return set()

BANNED_PASSWORDS = load_password_list('banned_passwords.txt')
WEAK_PASSWORDS = load_password_list('weak_passwords.txt')
DICTIONARY_WORDS = load_password_list('dictionary_words.txt')

def is_banned(password):
    return password.lower() in BANNED_PASSWORDS

def reverse_substitutions(password):
    sub_map = {
        '@': 'a', '0': 'o', '3': 'e', '$': 's', '!': 'i',
        '1': 'i', '5': 's', '#': 'h', '4': 'a', '7': 't',
        '²': '2', '€': 'e', '®': 'r', 'þ': 't', 'Ø': 'o',
        '2': 'z', '6': 'g', '9': 'g', '8': 'b'
    }
    return ''.join([sub_map.get(c.lower(), c) for c in password]).lower()

def is_weak_password(password):
    normalized = password.lower()
    return (normalized in WEAK_PASSWORDS or
            reverse_substitutions(password) in WEAK_PASSWORDS or
            normalized in DICTIONARY_WORDS)

def calculate_entropy(password):
    charset = 0
    has = {'lower': False, 'upper': False, 'digit': False, 'special': False}
    
    for c in password:
        if c.islower(): has['lower'] = True
        elif c.isupper(): has['upper'] = True
        elif c.isdigit(): has['digit'] = True
        else: has['special'] = True
    
    if has['lower']: charset += 26
    if has['upper']: charset += 26
    if has['digit']: charset += 10
    if has['special']: charset += 32
    
    return len(password) * math.log2(charset) if charset else 0

def check_common_patterns(password):
    patterns = [
        r'(.)\1{5,}',  # 6+ repeating characters
        r'\d{4,}',
        r'(?:abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)',
        r'(?:qwerty|asdfgh|zxcvbn|123456|654321)',
        r'(?:qwe|wer|ert|rty|tyu|yui|uio|iop|asd|sdf|dfg|fgh|ghj|hjk|jkl|zxcv|vbnm)',
        r'(?:love|hello|welcome|password|sunshine|princess|football|baseball|welcome1)',
        r'\b(?:summer|winter|spring|fall|autumn)\d{4}\b',
        r'\b(?:baby|hello|loveyou|iloveyou)\b',
        r'(?:[a-z]{2,}\d+|\d+[a-z]{2,})'
    ]
    return any(re.search(pattern, password.lower()) for pattern in patterns)

def complexity_score(password):
    score = 0
    length = len(password)
    
    # Length scoring
    score += min(length // 2, 8)
    
    # Character type scoring
    types = sum([
        any(c.islower() for c in password),
        any(c.isupper() for c in password),
        any(c.isdigit() for c in password),
        any(not c.isalnum() for c in password)
    ])
    score += types * 3
    
    # Deductions
    deductions = 0
    if check_common_patterns(password):
        deductions += 4
    if length < 12:
        deductions += 2
    if password.lower() in DICTIONARY_WORDS:
        deductions += 4
    if any(word in password.lower() for word in ['baby', 'hello', 'welcome']):
        deductions += 2
    
    return max(score - deductions, 0)

def check_pwned(password):
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
    try:
        response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5)
        hashes = [line.split(":")[0] for line in response.text.splitlines()]
        return suffix in hashes
    except requests.exceptions.RequestException:
        return False

def shannon_entropy(password):
    if not password:
        return 0
    entropy = 0
    length = len(password)
    for c in set(password):
        p = float(password.count(c)) / length
        entropy -= p * math.log(p, 2)
    return entropy

def nist_compliance(password):
    issues = []
    if len(password) < 8:
        issues.append("Password must be at least 8 characters long")
    if len(password) < 14:
        issues.append("NIST recommends 14+ characters for sensitive systems")
    if password.lower() in DICTIONARY_WORDS:
        issues.append("Password contains dictionary word")
    if any(word in password.lower() for word in ["user", "pass", "admin", "login"]):
        issues.append("Password contains context-specific terms")
    return issues

def password_strength(password):
    feedback = {
        'strength': 'Unbreakable',
        'score': 150,
        'issues': [],
        'warnings': [],
        'nist': [],
        'pwned': False,
        'entropy': 0
    }

    if is_banned(password):
        feedback.update({
            'strength': 'Banned',
            'score': 0,
            'issues': ['Password is in banned list']
        })
        return feedback

    # NIST Compliance Check
    feedback['nist'] = nist_compliance(password)
    
    # Pwned Passwords Check
    feedback['pwned'] = check_pwned(password)
    
    # Shannon Entropy
    feedback['entropy'] = shannon_entropy(password)

    # Existing password checks
    weak_reasons = []
    if is_weak_password(password):
        weak_reasons.append('in weak password list')
    if password.lower() in DICTIONARY_WORDS:
        weak_reasons.append('common dictionary word')
    if reverse_substitutions(password) in WEAK_PASSWORDS:
        weak_reasons.append('simple substitution pattern detected')

    if weak_reasons:
        feedback.update({
            'strength': 'Very Weak',
            'score': 10,
            'issues': [f'Password contains vulnerabilities: {", ".join(weak_reasons)}']
        })
        return feedback

    # Calculate metrics
    entropy = calculate_entropy(password)
    c_score = complexity_score(password)
    total_score = entropy + c_score * 3

    # Check for 6+ repeating characters
    if re.search(r'(.)\1{5,}', password):
        feedback['warnings'].append('6+ repeating characters detected')

    # Strength levels
    strength_levels = [
        (30, "Very Weak"),
        (50, "Weak"),
        (70, "Moderate"),
        (90, "Strong"),
        (120, "Very Strong"),
        (float('inf'), "Unbreakable")
    ]

    for threshold, strength in strength_levels:
        if total_score <= threshold:
            feedback['strength'] = strength
            feedback['score'] = total_score
            break

    # Add warnings
    if len(password) < 12:
        feedback['warnings'].append('Password too short (minimum 12 characters recommended)')
    if check_common_patterns(password):
        feedback['warnings'].append('Contains common patterns')
    if entropy < 60:
        feedback['warnings'].append('Low entropy (too predictable)')

    return feedback

def generate_strong_password(length=16):
    char_sets = {
        'lower': string.ascii_lowercase,
        'upper': string.ascii_uppercase,
        'digits': string.digits,
        'special': '!@#$%^&*()_+-=[]{}|;:,.<>?'
    }

    password = [
        random.choice(char_sets['lower']),
        random.choice(char_sets['upper']),
        random.choice(char_sets['digits']),
        random.choice(char_sets['special'])
    ]

    remaining = length - 4
    all_chars = ''.join(char_sets.values())
    password += random.choices(all_chars, k=remaining)
    random.shuffle(password)
    
    generated = ''.join(password)
    
    if password_strength(generated)['score'] < 100:
        return generate_strong_password(length)
    
    return generated

def cli_main():
    parser = argparse.ArgumentParser(description='Password Security Toolkit')
    parser.add_argument('password', nargs='?', help='Password to check')
    parser.add_argument('-g', '--generate', type=int, metavar='LENGTH',
                      help='Generate a strong password of specified length')
    args = parser.parse_args()

    if args.generate:
        if args.generate < 12:
            print("Warning: For security, minimum recommended length is 12")
        print(generate_strong_password(args.generate))
    elif args.password:
        # Analyze with custom algorithm
        result_custom = password_strength(args.password)
        
        # Analyze with zxcvbn
        result_zxcvbn = zxcvbn.zxcvbn(args.password)
        
        # Display results
        print(f"\nCustom Algorithm:")
        print(f"Strength: {result_custom['strength']}")
        print(f"Score: {result_custom['score']:.1f}/150")
        print(f"Shannon Entropy: {result_custom['entropy']:.1f} bits")
        
        if result_custom['pwned']:
            print("\n⚠️ WARNING: This password has been found in a data breach!")
        
        if result_custom['nist']:
            print("\nNIST Compliance Issues:")
            for issue in result_custom['nist']:
                print(f"• {issue}")
        
        if result_custom['issues']:
            print("\nCritical Issues:")
            for issue in result_custom['issues']:
                print(f"• {issue}")
        
        if result_custom['warnings']:
            print("\nWarnings:")
            for warning in result_custom['warnings']:
                print(f"• {warning}")
        
        print(f"\n\nzxcvbn Algorithm:")
        print(f"Strength: {result_zxcvbn['score']}/4")
        print(f"Crack Time: {result_zxcvbn['crack_times_display']['offline_slow_hashing_1e4_per_second']}")
        if result_zxcvbn['feedback']['warning']:
            print(f"\nFeedback: {result_zxcvbn['feedback']['warning']}")
        if result_zxcvbn['feedback']['suggestions']:
            print("\nSuggestions:")
            for suggestion in result_zxcvbn['feedback']['suggestions']:
                print(f"• {suggestion}")
    else:
        parser.print_help()

if __name__ == "__main__":
    cli_main()