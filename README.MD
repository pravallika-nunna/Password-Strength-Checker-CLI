# Password Strength Checker

## Description
The Password Strength Checker is a Python script designed to evaluate the strength and security of a password. It uses the following tools and methods to analyze passwords:

1. **OWASP Length Rating**: Rates the password length based on OWASP recommendations.
2. **Pwned Password Check**: Checks if the password has been exposed in known data breaches using the `Have I Been Pwned?` API.
3. **ZXCVBN Library**: Provides an in-depth strength analysis of the password, including feedback and estimated crack time.

## Features
- Rates password length based on OWASP standards.
- Checks if a password is part of known data breaches.
- Provides detailed password strength analysis, including:
  - Strength score (Very Weak to Very Strong).
  - Feedback on improving the password.
  - Estimated time to crack the password.
- Outputs whether the password has been compromised and the number of times it has appeared in breaches.

## Prerequisites
To run the script, ensure you have the following installed:
- Python 3.7 or later
- Required libraries:
  - `requests`
  - `zxcvbn` (Installable via `pip`)

## Installation
1. Clone or download this repository to your local machine.
2. Open a terminal and navigate to the directory containing the script.
3. Install the required dependencies:
   ```bash
   pip install requests zxcvbn
   ```

## Usage
1. Run the script:
   ```bash
   python password_strength_checker.py
   ```
2. Enter the password you want to evaluate when prompted.
3. Review the output, which includes:
   - Password Strength
   - Feedback for improving the password
   - Estimated crack time
   - Whether the password has been compromised (pwned) and how many times it has appeared in breaches.
   - OWASP length rating.

### Example
```bash
Enter your password: mySecureP@ssw0rd

Password Strength:
Strength: Strong
Feedback: Good password.
Crack Time: 3 days

Pwned Check:
Pwned: False
Pwned Count: 0

OWASP Length Rating:
Length Rating: 2
```

## How It Works
1. **OWASP Length Rating**: Determines a rating based on password length:
   - 0: Less than 12 characters
   - 1: 12-16 characters
   - 2: 17-32 characters
   - 3: 33-48 characters
   - 4: 49-64 characters
   - 5: Over 64 characters

2. **Pwned Password Check**: Hashes the password using SHA-1 and checks the first 5 characters of the hash against the `Have I Been Pwned?` API to see if it has been leaked.

3. **ZXCVBN Analysis**: Evaluates the password's complexity, provides feedback, and estimates the time required to crack it using various attack methods.

## File Descriptions

- **`password_checker.py`**: The main script containing the password strength evaluation logic.
- **`requirements.txt`**: Lists the required Python libraries for the project.

## Libraries Used

1. **`requests`**: For interacting with the "Have I Been Pwned" API.
2. **`hashlib`**: For hashing the password to check against the API.
3. **`zxcvbn`**: For evaluating password strength.

## Notes
- The script does not store passwords. All processing occurs locally except for the hash-based query to the `Have I Been Pwned?` API.
- Avoid entering real passwords directly into the tool in a shared environment or when running untrusted code.