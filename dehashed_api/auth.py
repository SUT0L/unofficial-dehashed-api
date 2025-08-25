import base64
import hashlib
import time
import secrets
import logging
from typing import Optional

try:
    import aiofiles
except ImportError:
    aiofiles = None

import aiohttp

logger = logging.getLogger(__name__)


async def login(
    username: str, 
    password: str, 
    state_key: Optional[str] = None
) -> tuple[str, str]:
    """
    Standalone login function for DeHashed.
    
    Args:
        username: DeHashed username/email
        password: DeHashed password
        state_key: Optional 32-character encryption key for session persistence
        
    Returns:
        Tuple of (auth_token, refresh_token)
    """
    if state_key:
        if not aiofiles:
            raise ImportError("aiofiles is required for session persistence. Install with: pip install aiofiles")
        
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError:
            raise ImportError("cryptography is required for session persistence. Install with: pip install cryptography")
            
        try:
            async with aiofiles.open(".cookie", "r") as f:
                cookie = await f.read()
                if cookie:
                    cookie = await __decrypt_session(state_key, cookie)
                    refresh_token, auth_token = cookie.split("|")
                    return auth_token, refresh_token
        except (FileNotFoundError, Exception):
            pass
    
    data = await __encode_payload(username, password, True)
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Referer': 'https://app.dehashed.com/'
    }
    
    async with aiohttp.ClientSession() as session:
        async with session.post(
            url='https://web-api.dehashed.com/authentication/login',
            json=data,
            headers=headers
        ) as resp:
            logger.info("Attempting to login")
            # get response as text first, then parse as JSON regardless of content type
            # this is because the website itself does not return a content type header
            text = await resp.text()
            
            if resp.status != 200:
                logger.error("Login failed: %s %s", resp.status, text[:200])
                raise Exception(f"Failed to login: {resp.status} {text}")

            refresh_token = resp.headers.get('Set-Cookie', '').split('refresh_token=')[1].split(';')[0] if 'refresh_token=' in resp.headers.get('Set-Cookie', '') else None
            
            try:
                import json
                response_data = json.loads(text)
                auth_token = response_data['auth_token']
            except (ValueError, KeyError) as e:
                raise Exception(f"Failed to parse login response: {text}") from e
    
    if state_key and aiofiles and refresh_token and auth_token:
        async with aiofiles.open(".cookie", "w") as f:
            session_data = f"{refresh_token}|{auth_token}"
            try:
                await f.write(await __encrypt_session(state_key, session_data))
            except ValueError as e:
                raise Exception(f"Failed to encrypt session: {e}")
    
    return auth_token, refresh_token


async def refresh_session(
    refresh_token: str, 
    state_key: Optional[str] = None
) -> str:
    """
    Refresh an existing session.
    
    Args:
        refresh_token: The refresh token
        state_key: Optional encryption key for session persistence
        
    Returns:
        New auth token
    """
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Referer': 'https://app.dehashed.com/',
        'Cookie': f'refresh_token={refresh_token}'
    }
    
    async with aiohttp.ClientSession() as session:
        session.cookie_jar.update_cookies({'refresh_token': refresh_token})
        
        async with session.post(
            url='https://web-api.dehashed.com/authentication/refresh',
            headers=headers
        ) as resp:
            logger.info("Refreshing auth token")
            # get response as text first, then parse as JSON regardless of content type
            text = await resp.text()
            
            if resp.status != 200:
                logger.error("Refresh failed: %s %s", resp.status, text[:200])
                raise Exception(f"Failed to refresh session: {resp.status} {text}")
            
            try:
                import json
                response_data = json.loads(text)
                new_auth_token = response_data['auth_token']
            except (ValueError, KeyError) as e:
                raise Exception(f"Failed to parse refresh response: {text}") from e
    
    # Save updated session if requested
    if state_key and aiofiles and new_auth_token:
        async with aiofiles.open(".cookie", "w") as f:
            session_data = f"{refresh_token}|{new_auth_token}"
            try:
                await f.write(await __encrypt_session(state_key, session_data))
            except ValueError as e:
                raise Exception(f"Failed to encrypt session: {e}")
    
    return new_auth_token


async def __encode_payload(email: str, password: str, remember_me: bool) -> dict:
    """Encode login payload with DeHashed's encryption scheme."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        raise ImportError("cryptography is required for authentication. Install with: pip install cryptography")
    
    def reverse_string(s):
        return s[::-1]
    
    def generate_random_string(length):
        return ''.join(secrets.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(length))
    
    async def encrypt_with_key(plaintext: str, key_string: str) -> str:
        key_bytes = key_string.encode('utf-8')
        iv_string = key_string[:16]
        iv_bytes = iv_string.encode('utf-8')
        aesgcm = AESGCM(key_bytes)
        encrypted = aesgcm.encrypt(iv_bytes, plaintext.encode('utf-8'), None)
        return base64.b64encode(encrypted).decode('utf-8')
    
    current_time_ms = int(time.time() * 1000)
    timestamp1 = str(current_time_ms)
    timestamp2 = str(current_time_ms + 10000)
    
    reversed_t1 = reverse_string(timestamp1)
    encryption_key = reversed_t1 + timestamp2 + reversed_t1[-6:]
    
    encoded_password = base64.b64encode(password.encode('utf-8')).decode('utf-8')
    composite = f"{email}:{encoded_password}:{str(remember_me).lower()}"
    reversed_composite = reverse_string(composite)
    
    encrypted_composite = await encrypt_with_key(reversed_composite, encryption_key)
    encrypted_heroine = await encrypt_with_key("aGVyb2luZQ==", encryption_key)
    encrypted_crack = await encrypt_with_key("Y3JhY2s=", encryption_key)
    encrypted_morphine = await encrypt_with_key("bW9ycGhpbmU=", encryption_key)
    
    composite_hash = hashlib.sha256(encrypted_composite.encode('utf-8')).hexdigest()
    random_data = generate_random_string(3) + encryption_key + generate_random_string(12)
    
    return {
        "db0": base64.b64encode(random_data.encode('utf-8')).decode('utf-8'),
        "dba0": generate_random_string(17) + encrypted_composite + generate_random_string(13),
        "dbamod0": generate_random_string(3) + reverse_string(composite_hash) + generate_random_string(7),
        "dbmod0": generate_random_string(36),
        "db1": encrypted_heroine,
        "db2": encrypted_crack,
        "db3": encrypted_morphine
    }


async def __encrypt_session(key: str, session: str) -> str:
    """Encrypt session data for storage."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        raise ImportError("cryptography is required for session encryption. Install with: pip install cryptography")
    
    iv = key[:16]
    cipher = AESGCM(key.encode('utf-8'))
    encrypted = cipher.encrypt(iv.encode('utf-8'), session.encode('utf-8'), None)
    return base64.b64encode(encrypted).decode('utf-8')


async def __decrypt_session(key: str, session: str) -> str:
    """Decrypt session data from storage."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        raise ImportError("cryptography is required for session decryption. Install with: pip install cryptography")
    
    iv = key[:16]
    cipher = AESGCM(key.encode('utf-8'))
    decrypted = cipher.decrypt(iv.encode('utf-8'), base64.b64decode(session), None)
    return decrypted.decode('utf-8')