from flask import Flask, request, render_template, jsonify
import json
import re
import datetime
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.exceptions import UnsupportedAlgorithm

app = Flask(__name__)

def detect_key_type(key_data):
    """Detect key type and encryption status."""
    result = {
        "format": None,
        "encrypted": False,
        "algorithm": None
    }
    
    # Check for PKCS#8 format
    if "-----BEGIN PRIVATE KEY-----" in key_data:
        result["format"] = "PKCS#8"
    
    # Check for PKCS#1 format
    elif "-----BEGIN RSA PRIVATE KEY-----" in key_data:
        result["format"] = "PKCS#1"
        
        # Check if encrypted
        if "ENCRYPTED" in key_data:
            result["encrypted"] = True
            # Extract encryption algorithm if present
            dek_match = re.search(r'DEK-Info: ([^,]+)', key_data)
            if dek_match:
                result["algorithm"] = dek_match.group(1)
    
    return result

def load_private_key(key_data, password=None):
    """Load the private key from PEM format."""
    try:
        password_bytes = password.encode() if password else None
        private_key = load_pem_private_key(
            key_data.encode(),
            password=password_bytes,
            backend=default_backend()
        )
        return private_key, None
    except ValueError as e:
        if "bad password" in str(e).lower() or "decryption failed" in str(e).lower():
            return None, "Incorrect password for encrypted key"
        return None, f"Invalid key format: {str(e)}"
    except UnsupportedAlgorithm:
        return None, "Unsupported key algorithm"
    except Exception as e:
        return None, f"Error loading key: {str(e)}"

def generate_jwt(private_key, payload, algorithm="RS256", expiry_minutes=60, headers=None):
    """Generate a JWT using the provided private key and payload."""
    try:
        # Parse the payload JSON
        if isinstance(payload, str):
            try:
                payload_dict = json.loads(payload)
            except json.JSONDecodeError:
                return None, "Invalid JSON payload format"
        else:
            payload_dict = payload
            
        # Add standard JWT claims if not present
        if "exp" not in payload_dict:
            expiry_time = datetime.datetime.utcnow() + datetime.timedelta(minutes=expiry_minutes)
            payload_dict["exp"] = expiry_time
            
        if "iat" not in payload_dict:
            payload_dict["iat"] = datetime.datetime.utcnow()
        
        # Generate the JWT
        token = jwt.encode(
            payload_dict,
            private_key,
            algorithm=algorithm,
            headers=headers
        )
        
        return token, None
    except Exception as e:
        return None, f"Error generating JWT: {str(e)}"

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        private_key_data = request.form.get('private_key', '')
        password = request.form.get('password', '')
        payload = request.form.get('payload', '{}')
        headers = request.form.get('headers', '{}')
        expiry_minutes = int(request.form.get('expiry', 60))
        
        # Detect key type
        key_info = detect_key_type(private_key_data)
        
        # Check if the key is encrypted but no password provided
        if key_info["encrypted"] and not password:
            return render_template('index.html', 
                                  error="Key is encrypted. Please provide a password.",
                                  key_info=key_info)
        
        # Load the private key
        private_key, error = load_private_key(private_key_data, password)
        if error:
            return render_template('index.html', 
                                  error=error,
                                  key_info=key_info)
        
        # Parse headers JSON
        try:
            headers_dict = json.loads(headers) if headers else None
        except json.JSONDecodeError:
            return render_template('index.html',
                                  error="Invalid JSON headers format",
                                  key_info=key_info)
        
        # Generate JWT
        token, error = generate_jwt(private_key, payload, expiry_minutes=expiry_minutes, headers=headers_dict)
        if error:
            return render_template('index.html', 
                                  error=error,
                                  key_info=key_info)
        
        bearer_token = f"Bearer {token}"
        
        return render_template('index.html',
                              key_info=key_info,
                              bearer_token=bearer_token,
                              payload_display=json.dumps(json.loads(payload), indent=2),
                              headers_display=json.dumps(headers_dict, indent=2) if headers_dict else None)
    
    return render_template('index.html')

@app.template_filter('jsonformat')
def jsonformat_filter(s):
    try:
        return json.dumps(json.loads(s), indent=2)
    except:
        return s

if __name__ == '__main__':
    app.run(debug=True)