import requests
import hashlib
from zxcvbn import zxcvbn


class PasswordStrengthChecker:
    def owasp_length_rating(self, password: str) -> int:
        """Rates the password length based on OWASP recommendations."""
        length = len(password)
        if 12 <= length <= 16:
            return 1
        elif 17 <= length <= 32:
            return 2
        elif 33 <= length <= 48:
            return 3
        elif 49 <= length <= 64:
            return 4
        elif length > 64:
            return 5
        return 0  # For passwords shorter than 12 characters

    def pwned_password_check(self, password: str) -> dict:
        """Checks if the password has been exposed in any known data breaches."""
        sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        url = f"https://api.pwnedpasswords.com/range/{sha1_hash[:5]}"
        try:
            response = requests.get(url)
            response.raise_for_status()
            hashes = response.text.splitlines()
            for hash_count in hashes:
                if hash_count.startswith(sha1_hash[5:]):
                    count = int(hash_count.split(":")[1])
                    return {"pwned": True, "count": count}
        except requests.exceptions.RequestException:
            return {"pwned": False, "count": 0}
        return {"pwned": False, "count": 0}

    def zxcvbn_password_strength(self, password: str) -> dict:
        """Checks the password strength using the zxcvbn library."""
        result = zxcvbn(password)
        score = result["score"]
        strength = ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"][score]
        feedback = result["feedback"]["suggestions"] or ["Good password."]
        crack_time = result["crack_times_display"]["online_no_throttling_10_per_second"]
        pwned_info = self.pwned_password_check(password)
        length_rating = self.owasp_length_rating(password)
        return {
            "strength": strength,
            "feedback": feedback,
            "crack_time": crack_time,
            "pwned": pwned_info["pwned"],
            "pwned_count": pwned_info["count"],
            "length_rating": length_rating,
        }


if __name__ == "__main__":
    checker = PasswordStrengthChecker()
    password = input("Enter your password: ")

    result = checker.zxcvbn_password_strength(password)

    # Display the results
    print("\nPassword Strength:")
    print(f"Strength: {result['strength']}")
    print(f"Feedback: {' '.join(result['feedback'])}")
    print(f"Crack Time: {result['crack_time']}")

    print("\nPwned Check:")
    print(f"Pwned: {result['pwned']}")
    print(f"Pwned Count: {result['pwned_count']}")

    print("\nOWASP Length Rating:")
    print(f"Length Rating: {result['length_rating']}")