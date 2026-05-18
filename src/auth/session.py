import secrets

def generate_session_token():
    # Generate a cryptographically secure random session token
    # Using 6 digits to maintain the original format
    token_int = secrets.randbelow(900000) + 100000  # ensures a value between 100000 and 999999 inclusive
    return str(token_int)