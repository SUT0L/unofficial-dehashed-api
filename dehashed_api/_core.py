import base64
import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from .types import DehashedResult, SearchParams, SearchResponse
import logging

logger = logging.getLogger(__name__)


class DehashedAPIError(Exception):
    def __init__(self, message: str, status_code: Optional[int] = None):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)


class RateLimiterState:
    def __init__(self) -> None:
        self.limit = 50
        self.remaining = 50
        self.reset = 3
        self.reset_at: Optional[datetime] = None
        self.retry_after: Optional[int] = None

    def update_from_headers(self, headers: Dict[str, str]) -> None:
        if 'x-ratelimit-limit' in headers:
            self.limit = int(headers['x-ratelimit-limit'])
        if 'x-ratelimit-remaining' in headers:
            self.remaining = int(headers['x-ratelimit-remaining'])
        if 'x-ratelimit-reset' in headers:
            self.reset = int(headers['x-ratelimit-reset'])
            self.reset_at = datetime.now() + timedelta(seconds=self.reset)
        if 'retry-after' in headers:
            self.retry_after = int(headers['retry-after'])
        logger.debug("rate-limit update: limit=%s remaining=%s reset=%s retry-after=%s", 
                    self.limit, self.remaining, self.reset, self.retry_after)

def _generate_random_hex(length: int) -> str:
    byte_length = length // 2
    random_bytes = secrets.token_bytes(byte_length)
    return random_bytes.hex()


def _reverse_string(s: str) -> str:
    return s[::-1]


def _create_sha256_hash(s: str | bytes) -> str:
    if isinstance(s, str):
        s = s.encode('utf-8')
    return hashlib.sha256(s).hexdigest()


def _aes_gcm_encrypt(plaintext: str, key: str, iv: str) -> str:
    try:
        from Crypto.Cipher import AES
    except ImportError as e:
        raise ImportError("pycryptodome is required for AES encryption. Install with: pip install dehashed-api[crypto]") from e

    key_bytes = key.encode('utf-8')
    iv_bytes = iv.encode('utf-8')
    plaintext_bytes = plaintext.encode('utf-8')

    if len(key_bytes) < 32:
        key_bytes = key_bytes.ljust(32, b'\0')
    elif len(key_bytes) > 32:
        key_bytes = key_bytes[:32]

    cipher = AES.new(key_bytes, AES.MODE_GCM, iv_bytes)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext_bytes)
    return base64.b64encode(ciphertext + tag).decode('utf-8')


def encrypt_with_auth_token(s: str, auth_token: str | None) -> str:
    if not auth_token:
        raise DehashedAPIError("No auth token available for encryption")
    iv = auth_token[:16]
    key = auth_token[:32]
    return _aes_gcm_encrypt(s, key, iv)


def build_search_payload(params: SearchParams, auth_token: str | None) -> Dict[str, Any]:
    try:
        encrypted_query = encrypt_with_auth_token(params.query, auth_token)
        hashed = _create_sha256_hash(encrypted_query)
        rhex = _generate_random_hex(32)
        rhex_rev = _reverse_string(rhex)
        r2 = rhex + hashed + rhex_rev
        encrypted_type = encrypt_with_auth_token(params.search_type, auth_token)
        return {
            "r0": encrypted_query,
            "page": params.page,
            "r2": r2,
            "r1": encrypted_type,
            "regex": params.regex,
            "wildcard": params.wildcard,
            "deduplicate": params.deduplicate,
        }
    except Exception as e:
        raise DehashedAPIError(f"Error generating search payload: {e}")


def parse_search_response(data: Dict[str, Any]) -> SearchResponse:
    results: List[DehashedResult] = []
    for item in data.get('results', []):
        results.append(
            DehashedResult(
                id=item.get('id', ''),
                primary_field=item.get('primary_field', ''),
                email=item.get('email', []),
                name=item.get('name', []),
                address=item.get('address', []),
                phone=item.get('phone', []),
                company=item.get('company', []),
                url=item.get('url', []),
                database_name=item.get('database_name', ''),
                password=item.get('password', []),
                hashed_password=item.get('hashed_password', []),
            )
        )

    return SearchResponse(
        assets_searched=data.get('assets_searched', 0),
        data_wells=data.get('data_wells', 0),
        total_results=data.get('total_results', 0),
        next_page=data.get('next_page', False),
        elapsed_time=data.get('elapsed_time', 0),
        results=results,
        has_access=data.get('has_access', False),
    )


