"""
HeapHunter - Utility Functions

This module contains utility functions for string processing,
decoding, and pattern matching used across the HeapHunter application.
"""

import re
import base64
import json
from typing import Dict, List, Set, Tuple, Any, Optional, Union

# Try to import crypto libraries - graceful fallback if not available
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("[WARNING] PyCryptodome not installed. AES decryption will not be available.")
    print("          Install with: pip install pycryptodome")


# Regular expression patterns for sensitive data
SENSITIVE_PATTERNS = {
    'jwt': re.compile(r'(eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})'),
    'bcrypt': re.compile(r'(\$2[aby]\$.{56})'),
    'sha256': re.compile(r'([a-fA-F0-9]{64})'),
    'sha1/md5': re.compile(r'([a-fA-F0-9]{32})'),
    'tokens': re.compile(r'(?i)(bearer|token|secret|apikey)[=: ]+([^\s"\']{10,})'),
    'base64': re.compile(r'([A-Za-z0-9+/=]{40,})'),
}

# Credential key blacklist for filtering false positives
CREDENTIAL_KEY_BLACKLIST = [
    "key", "keys", "field", "factory", "method", "clazz", "type", 
    "Token", "Deserializer", "Deserializer", "Generator", "Handler",
    "Iterator", "Map", "HashMap", "Set", "Value", "Operation", "Parameter", 
    "Builder", "Strategy", "Node", "Object", "Thread", "ByteBuf",
    "invoke", "LambdaForm", "java/", "javax/", "org/", "sun/", "jdk/"
]


def is_likely_key_name(s: str) -> bool:
    """Check if a string looks like a key name.
    
    Args:
        s: String to check
        
    Returns:
        True if the string looks like a key name
    """
    s = s.strip()
    if len(s) > 100:
        return False
    if not re.match(r'^[a-zA-Z0-9_.\-]+[!:]$', s):
        return False
    if any(kw in s.lower() for kw in ['password', 'user', 'token', 'secret', 'key', 'auth', 'jwt']):
        return True
    return False


def is_probable_key(s: str) -> bool:
    """Check if a string is likely to be a key name.
    
    Args:
        s: String to check
        
    Returns:
        True if it's likely a key name
    """
    s = s.strip()
    if len(s) > 100:
        return False
    if not re.match(r'^[a-zA-Z0-9_.\-]+[!:]$', s):
        return False
    if any(kw in s.lower() for kw in ['password', 'user', 'username', 'token', 'secret', 'key', 'auth', 'jwt']):
        return True
    return False


def is_real_value(val: str) -> bool:
    """Check if a string is likely to be a real value (not Java path or garbage).
    
    Args:
        val: String to check
        
    Returns:
        True if the string is likely a real value
    """
    if not val or len(val) < 3:
        return False
    if any(s in val for s in ['/', '.', '$', ';', 'Lorg', 'Ljava', 'io.', 'org.', 'java.', 'net.', 'jakarta.']):
        return False
    return True


def is_strong_candidate(pw: str) -> bool:
    """Check if a password is strong (contains letters and numbers).
    
    Args:
        pw: Password to check
        
    Returns:
        True if the password is strong
    """
    if len(pw) < 8:
        return False
    if not re.search(r"[a-zA-Z]", pw):
        return False
    if not re.search(r"[0-9]", pw):
        return False
    return True


def is_plausible_credential(key: str, value: str) -> bool:
    """Check if a key-value pair is likely to be a credential.
    
    Args:
        key: Key string
        value: Value string
        
    Returns:
        True if it's likely a credential
    """
    key_lower = key.lower()
    value = value.strip().strip('#!;:=')
    
    # If key is blacklisted, discard
    if any(blk in key_lower for blk in CREDENTIAL_KEY_BLACKLIST):
        return False
    
    # If key matches known credential patterns, accept
    if any(kw in key_lower for kw in ['password', 'secret', 'token', 'key', 'jwt', 'username', 'user']):
        return True
    
    # If value is base64-like and long enough, accept
    if len(value) >= 20 and re.match(r'^[A-Za-z0-9+/=]+$', value):
        return True
    
    # If looks like a strong password
    if is_strong_candidate(value):
        return True
    
    return False


def try_decode_base64(s: str) -> Optional[str]:
    """Try to decode a string as base64.
    
    Args:
        s: String to decode
        
    Returns:
        Decoded string or None if failed
    """
    if not s:
        return None
        
    s = s.strip().rstrip('#!;')
    try:
        decoded = base64.b64decode(s + '=' * (-len(s) % 4)).decode(errors='ignore')
        return decoded if decoded.strip() else None
    except Exception:
        return None


def try_parse_json(s: str) -> Optional[Dict]:
    """Try to parse a string as JSON.
    
    Args:
        s: String to parse
        
    Returns:
        Parsed JSON object or None if failed
    """
    if not s:
        return None
    try:
        return json.loads(s)
    except Exception:
        return None


def try_decrypt_base64_ciphertext(ciphertext_b64: str, keys: List[str]) -> List[Dict]:
    """Try to decrypt a base64-encoded ciphertext using various keys.
    
    Args:
        ciphertext_b64: Base64-encoded ciphertext
        keys: List of potential decryption keys
        
    Returns:
        List of successful decryption results
    """
    if not CRYPTO_AVAILABLE:
        return []
        
    results = []
    try:
        ciphertext = base64.b64decode(ciphertext_b64)
    except Exception:
        return results
    
    iv_guesses = [ciphertext[:16], b'\x00' * 16]
    
    for key in keys:
        key_bytes = key.encode()[:32].ljust(32, b'\0')
        for iv in iv_guesses:
            try:
                cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
                decrypted = unpad(cipher.decrypt(ciphertext[16:]), AES.block_size)
                decoded = decrypted.decode('utf-8')
                if is_readable(decoded):
                    results.append({
                        'key': key,
                        'iv': iv.hex(),
                        'decrypted': decoded
                    })
            except Exception:
                continue
    return results


def is_readable(s: str) -> bool:
    """Check if a string is humanly readable.
    
    Args:
        s: String to check
        
    Returns:
        True if the string is readable
    """
    return any(c.isalnum() for c in s) and all(31 < ord(c) < 127 or c in '\n\r\t' for c in s)


def pad_base64(s: str) -> str:
    """Pad a base64 string to the correct length.
    
    Args:
        s: String to pad
        
    Returns:
        Padded string
    """
    return s + "=" * (-len(s) % 4)


def decode_jwt_parts(jwt_str: str) -> Optional[Tuple[str, str]]:
    """Decode JWT header and payload parts.
    
    Args:
        jwt_str: JWT token string
        
    Returns:
        Tuple of (header, payload) or None if failed
    """
    try:
        parts = jwt_str.split(".")
        if len(parts) < 2:
            return None
        
        header = base64.urlsafe_b64decode(pad_base64(parts[0])).decode('utf-8', errors='ignore')
        payload = base64.urlsafe_b64decode(pad_base64(parts[1])).decode('utf-8', errors='ignore')
        return header, payload
    except Exception:
        return None
