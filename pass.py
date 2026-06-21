import re
import string
import getpass

class PasswordStrengthChecker:
    def __init__(self):
        # Define character sets
        self.lowercase = string.ascii_lowercase
        self.uppercase = string.ascii_uppercase
        self.digits = string.digits
        self.special_chars = string.punctuation
        
        # Common weak passwords (you can expand this)
        self.common_passwords = {
            'password', '123456', '12345678', '123456789', 'qwerty', 
            'abc123', 'password123', 'admin', 'letmein', 'welcome',
            'monkey', 'dragon', 'master', 'hello', 'freedom',
            'whatever', 'michael', 'jennifer', 'superman', 'trustno1'
        }
    
    def check_length(self, password):
        """Check password length"""
        length = len(password)
        if length < 8:
            return 0, "Too short (minimum 8 characters)"
        elif length < 12:
            return 1, "Good length (8-11 characters)"
        elif length < 16:
            return 2, "Great length (12-15 characters)"
        else:
            return 3, "Excellent length (16+ characters)"
    
    def check_complexity(self, password):
        """Check character diversity"""
        score = 0
        details = []
        
        # Check for lowercase
        if any(c in self.lowercase for c in password):
            score += 1
            details.append("✅ Contains lowercase letters")
        else:
            details.append("❌ Missing lowercase letters")
        
        # Check for uppercase
        if any(c in self.uppercase for c in password):
            score += 1
            details.append("✅ Contains uppercase letters")
        else:
            details.append("❌ Missing uppercase letters")
        
        # Check for digits
        if any(c in self.digits for c in password):
            score += 1
            details.append("✅ Contains numbers")
        else:
            details.append("❌ Missing numbers")
        
        # Check for special characters
        if any(c in self.special_chars for c in password):
            score += 1
            details.append("✅ Contains special characters")
        else:
            details.append("❌ Missing special characters")
        
        return score, details
    
    def check_patterns(self, password):
        """Check for common patterns and sequences"""
        score = 0
        warnings = []
        
        # Convert to lowercase for pattern checking
        pwd_lower = password.lower()
        
        # Check for common passwords
        if pwd_lower in self.common_passwords:
            warnings.append("⚠️ Password is too common")
            return 0, warnings
        
        # Check for keyboard patterns
        keyboard_patterns = ['qwerty', 'asdfgh', 'zxcvbn', 'qwertyuiop', 'asdfghjkl']
        for pattern in keyboard_patterns:
            if pattern in pwd_lower:
                warnings.append(f"⚠️ Contains keyboard pattern: '{pattern}'")
                score -= 1
        
        # Check for sequential numbers
        for i in range(len(password) - 2):
            if password[i:i+3].isdigit():
                if int(password[i+1]) == int(password[i]) + 1 and int(password[i+2]) == int(password[i+1]) + 1:
                    warnings.append(f"⚠️ Contains sequential numbers: '{password[i:i+3]}'")
                    score -= 1
                    break
        
        # Check for repeated characters
        for i in range(len(password) - 2):
            if password[i] == password[i+1] == password[i+2]:
                warnings.append(f"⚠️ Contains repeated characters: '{password[i]*3}'")
                score -= 1
                break
        
        # Check for common date patterns
        date_patterns = ['2020', '2021', '2022', '2023', '2024', '2025']
        for pattern in date_patterns:
            if pattern in password:
                warnings.append(f"⚠️ Contains year pattern: '{pattern}'")
                score -= 1
                break
        
        return score, warnings
    
    def calculate_entropy(self, password):
        """Calculate password entropy"""
        char_set_size = 0
        if any(c in self.lowercase for c in password):
            char_set_size += 26
        if any(c in self.uppercase for c in password):
            char_set_size += 26
        if any(c in self.digits for c in password):
            char_set_size += 10
        if any(c in self.special_chars for c in password):
            char_set_size += len(self.special_chars)
        
        if char_set_size == 0:
            return 0
        
        entropy = len(password) * (char_set_size.bit_length())
        return entropy
    
    def check_strength(self, password):
        """Main function to check password strength"""
        results = {
            'score': 0,
            'max_score': 10,
            'strength': '',
            'details': [],
            'warnings': [],
            'entropy': 0
        }
        
        # Check length
        length_score, length_msg = self.check_length(password)
        results['score'] += length_score
        results['details'].append(f"Length: {length_msg}")
        
        # Check complexity
        complexity_score, complexity_details = self.check_complexity(password)
        results['score'] += complexity_score
        results['details'].extend(complexity_details)
        
        # Check patterns
        pattern_score, warnings = self.check_patterns(password)
        results['score'] += pattern_score
        results['warnings'].extend(warnings)
        
        # Calculate entropy
        results['entropy'] = self.calculate_entropy(password)
        
        # Determine strength level
        if results['score'] >= 9:
            results['strength'] = "🌟 EXCELLENT"
        elif results['score'] >= 7:
            results['strength'] = "💪 STRONG"
        elif results['score'] >= 5:
            results['strength'] = "👍 GOOD"
        elif results['score'] >= 3:
            results['strength'] = "⚠️ WEAK"
        else:
            results['strength'] = "🔴 VERY WEAK"
        
        # Ensure score is within bounds
        results['score'] = max(0, min(results['score'], results['max_score']))
        
        return results
    
    def display_results(self, results):
        """Display password strength results in a formatted way"""
        print("\n" + "="*50)
        print(f"PASSWORD STRENGTH: {results['strength']}")
        print("="*50)
        print(f"Score: {results['score']}/{results['max_score']}")
        print(f"Entropy: {results['entropy']} bits")
        print("\nDETAILS:")
        for detail in results['details']:
            print(f"  {detail}")
        
        if results['warnings']:
            print("\n⚠️ WARNINGS:")
            for warning in results['warnings']:
                print(f"  {warning}")
        
        # Recommendations
        print("\n💡 RECOMMENDATIONS:")
        if results['score'] < 7:
            if results['score'] < 5:
                print("  • Use at least 12 characters")
                print("  • Include uppercase, lowercase, numbers, and special characters")
                print("  • Avoid common words and patterns")
            if any("Missing" in detail for detail in results['details']):
                print("  • Add missing character types")
            if results['warnings']:
                print("  • Remove common patterns and sequences")
        else:
            print("  ✓ Your password is strong! Keep it safe and unique.")
        
        print("="*50 + "\n")

def main():
    """Main function to run the password checker"""
    checker = PasswordStrengthChecker()
    
    print("🔐 PASSWORD STRENGTH CHECKER 🔐")
    print("Your password will be evaluated based on:")
    print("  • Length (8+ characters recommended)")
    print("  • Character diversity (uppercase, lowercase, numbers, special chars)")
    print("  • Common patterns and sequences")
    print("  • Entropy (randomness)")
    print("\n" + "-"*50)
    
    while True:
        print("\nOptions:")
        print("1. Check a password (hidden input)")
        print("2. Check a password (visible input)")
        print("3. Generate a strong password suggestion")
        print("4. Exit")
        
        choice = input("\nEnter your choice (1-4): ").strip()
        
        if choice == '1':
            password = getpass.getpass("Enter password to check: ")
            if password:
                results = checker.check_strength(password)
                checker.display_results(results)
            else:
                print("❌ Password cannot be empty!")
        
        elif choice == '2':
            password = input("Enter password to check: ")
            if password:
                results = checker.check_strength(password)
                checker.display_results(results)
            else:
                print("❌ Password cannot be empty!")
        
        elif choice == '3':
            generate_password_suggestion()
        
        elif choice == '4':
            print("👋 Goodbye!")
            break
        
        else:
            print("❌ Invalid choice. Please try again.")

def generate_password_suggestion():
    """Generate a strong password suggestion"""
    import random
    import secrets
    
    # Generate a strong password
    length = 16
    chars = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(chars) for _ in range(length))
    
    print("\n💡 SUGGESTED STRONG PASSWORD:")
    print(f"  {password}")
    print("  (Length: 16 characters, includes all character types)")
    print("  💡 Tip: Use a password manager to generate and store strong passwords!")

if __name__ == "__main__":
    main()