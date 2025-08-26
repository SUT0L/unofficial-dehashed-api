import time
from datetime import datetime
import logging
from typing import Any, Dict, Iterator, Optional, cast

from ._core import (
    DehashedAPIError,
    RateLimiterState,
    build_search_payload,
    parse_search_response,
)
from .types import RequestConfig, SearchParams, SearchResponse, DehashedResult, SearchType


class Client:
    def __init__(
        self,
        username: Optional[str] = None,
        password: Optional[str] = None,
        auth_token: Optional[str] = None,
        state_key: Optional[str] = None,
        base_url: str = "https://web-api.dehashed.com",
        auto_refresh: bool = True,
        save_cookie: bool = False,
        request_timeout: float = 30.0,
    ) -> None:
        if not auth_token and (not username or not password):
            raise ValueError("Either auth_token or both username and password must be provided")

        if save_cookie and not state_key:
            raise ValueError("state_key is required when save_cookie=True")

        if state_key and len(state_key) != 32:
            raise ValueError("state_key must be exactly 32 characters long")

        self.username = username
        self.password = password
        self.auth_token = auth_token
        self.refresh_token: Optional[str] = None
        self.state_key = state_key
        self.base_url = base_url
        self.auto_refresh = auto_refresh
        self.save_cookie = save_cookie
        self.request_timeout = request_timeout
        self.rate = RateLimiterState()

        self.default_headers = {
            "Accept": "*/*",
            "Content-Type": "application/json",
            "Referer": "https://app.dehashed.com/",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
        }
        self._logger = logging.getLogger(__name__)

        if self.username and self.password and self.save_cookie and self.state_key:
            self._load_session()

    def _load_session(self) -> None:
        if not self.state_key:
            return
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401
        except ImportError:
            raise ImportError("cryptography is required for session persistence. Install with: pip install cryptography")
        try:
            with open(".cookie", "r") as f:
                cookie = f.read()
                if cookie:
                    decrypted = self._decrypt_session(self.state_key, cookie)
                    self.refresh_token, self.auth_token = decrypted.split("|")
        except (FileNotFoundError, Exception):
            pass

    def _save_session(self) -> None:
        if self.save_cookie and self.state_key and self.refresh_token and self.auth_token:
            try:
                session_data = f"{self.refresh_token}|{self.auth_token}"
                encrypted = self._encrypt_session(self.state_key, session_data)
                with open(".cookie", "w") as f:
                    f.write(encrypted)
            except Exception:
                pass

    def _encrypt_session(self, key: str, session: str) -> str:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError:
            raise ImportError("cryptography is required for session encryption. Install with: pip install cryptography")
        import base64, secrets
        nonce = secrets.token_bytes(12)
        cipher = AESGCM(key.encode("utf-8"))
        ciphertext = cipher.encrypt(nonce, session.encode("utf-8"), None)
        return base64.b64encode(nonce + ciphertext).decode("utf-8")

    def _decrypt_session(self, key: str, session: str) -> str:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError:
            raise ImportError("cryptography is required for session decryption. Install with: pip install cryptography")
        import base64
        raw = base64.b64decode(session)
        cipher = AESGCM(key.encode("utf-8"))
        try:
            nonce = raw[:12]
            ciphertext = raw[12:]
            decrypted = cipher.decrypt(nonce, ciphertext, None)
            return decrypted.decode("utf-8")
        except Exception:
            iv = key[:16].encode("utf-8")
            decrypted = cipher.decrypt(iv, raw, None)
            return decrypted.decode("utf-8")

    def _login_sync(self) -> None:
        try:
            import asyncio
            asyncio.get_running_loop()
            raise RuntimeError("Cannot perform synchronous login inside a running event loop. Use the async APIs.")
        except RuntimeError:
            pass
        import asyncio
        if not self.username or not self.password:
            raise DehashedAPIError("Username and password required for login")
        try:
            auth_token, refresh_token = asyncio.run(self._login_async_helper())
            self.auth_token = auth_token
            self.refresh_token = refresh_token
        except Exception as e:
            raise DehashedAPIError(f"Login failed: {e}")
        self._save_session()

    async def _login_async_helper(self) -> tuple[str, str]:
        from .auth import login
        return await login(
            username=self.username,
            password=self.password,
            state_key=self.state_key if self.save_cookie else None,
        )

    def _refresh_token_sync(self) -> None:
        try:
            import asyncio
            asyncio.get_running_loop()
            raise RuntimeError("Cannot refresh synchronously inside a running event loop. Use the async APIs.")
        except RuntimeError:
            pass
        import asyncio
        if not self.refresh_token:
            raise DehashedAPIError("No refresh token available")
        try:
            self.auth_token = asyncio.run(self._refresh_async_helper())
        except Exception as e:
            raise DehashedAPIError(f"Token refresh failed: {e}")
        self._save_session()

    async def _refresh_async_helper(self) -> str:
        from .auth import refresh_session
        return await refresh_session(
            refresh_token=self.refresh_token,
            state_key=self.state_key if self.save_cookie else None,
        )

    def _ensure_auth_sync(self) -> None:
        try:
            import asyncio
            asyncio.get_running_loop()
            raise RuntimeError("Cannot use synchronous client methods inside a running event loop. Use async variants.")
        except RuntimeError:
            pass
        if not self.auth_token:
            if self.username and self.password:
                self._login_sync()
            else:
                raise DehashedAPIError("No auth token and no credentials for login")

    def generate_search_request(self, params: SearchParams, custom_headers: Optional[Dict[str, str]] = None) -> RequestConfig:
        payload = build_search_payload(params, self.auth_token)
        headers = self.default_headers.copy()
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"
        if custom_headers:
            headers.update(custom_headers)
        return RequestConfig(
            url=f"{self.base_url}/search",
            method="POST",
            headers=headers,
            payload=payload,
        )

    def execute_request(self, request: RequestConfig, max_retries: int = 3) -> Dict[str, Any]:
        try:
            import requests
        except ImportError:
            raise ImportError("requests is required for synchronous operations. Install with: pip install dehashed-api[sync]")

        retries = 0
        while retries <= max_retries:
            self._ensure_auth_sync()
            request.headers["Authorization"] = f"Bearer {self.auth_token}"
            self._logger.debug("POST %s", request.url)
            if self.rate.remaining <= 0 and self.rate.reset_at:
                sleep_for = max(0, (self.rate.reset_at - datetime.now()).total_seconds() + 1)
                time.sleep(sleep_for)
                self.rate.remaining = self.rate.limit

            response = requests.post(
                url=request.url,
                headers=request.headers,
                json=request.payload,
                timeout=self.request_timeout,
            )
            self._logger.debug("POST %s -> %s", request.url, response.status_code)
            self.rate.update_from_headers(response.headers)

            if response.status_code == 429:
                if self.rate.retry_after is not None:
                    backoff_time = self.rate.retry_after
                else:
                    backoff_time = 40
                self._logger.warning("429 received; backing off %ss", backoff_time)
                time.sleep(backoff_time)
                self.rate.remaining = self.rate.limit
                self.rate.retry_after = None
                continue
            elif response.status_code in [401, 403] and self.auto_refresh and retries < max_retries:
                if self.refresh_token:
                    try:
                        self._logger.info("Refreshing token")
                        self._refresh_token_sync()
                        retries += 1
                        continue
                    except DehashedAPIError:
                        pass
                if self.username and self.password:
                    try:
                        self._logger.info("Re-logging in")
                        self._login_sync()
                        retries += 1
                        continue
                    except DehashedAPIError:
                        pass
                try:
                    data = response.json()
                    error_msg = data.get('message', f"Authentication failed: {response.status_code}")
                except Exception:
                    error_msg = f"Authentication failed: {response.status_code}"
                self._logger.error("Auth error: %s", error_msg)
                raise DehashedAPIError(error_msg, response.status_code)
            elif response.status_code != 200:
                try:
                    data = response.json()
                    error_msg = data.get('message', f"Error: {response.status_code}")
                except Exception:
                    error_msg = f"Error: {response.status_code}"
                self._logger.error("Request error: %s", error_msg)
                raise DehashedAPIError(error_msg, response.status_code)

            return response.json()

    def search(
        self,
        search_type: str | SearchType,
        query: str,
        page: int = 1,
        regex: bool = False,
        wildcard: bool = False,
        deduplicate: bool = True,
        custom_headers: Optional[Dict[str, str]] = None,
        as_object: bool = True,
    ) -> Dict[str, Any] | SearchResponse:
        params = SearchParams(
            search_type=search_type.value if isinstance(search_type, SearchType) else search_type,
            query=query,
            page=page,
            regex=regex,
            wildcard=wildcard,
            deduplicate=deduplicate,
        )
        request = self.generate_search_request(params, custom_headers)
        data = self.execute_request(request)
        if as_object:
            return parse_search_response(data)
        return data

    def paginate_search(
        self,
        search_type: str | SearchType,
        query: str,
        max_pages: int = 10,
        regex: bool = False,
        wildcard: bool = False,
        deduplicate: bool = True,
        custom_headers: Optional[Dict[str, str]] = None,
        as_object: bool = True,
    ) -> Iterator[DehashedResult] | Iterator[Dict[str, Any]]:
        page = 1
        while page <= max_pages:
            self._logger.debug("paginate page=%s", page)
            response = self.search(
                search_type=search_type,
                query=query,
                page=page,
                regex=regex,
                wildcard=wildcard,
                deduplicate=deduplicate,
                custom_headers=custom_headers,
                as_object=as_object,
            )
            if as_object:
                response_obj = cast(SearchResponse, response)
                if not response_obj.results:
                    break
                for result in response_obj.results:
                    yield result
                if not response_obj.next_page:
                    break
            else:
                results = response.get('results', [])
                if not results:
                    break
                for result in results:
                    yield result
                if not response.get('next_page', False):
                    break
            page += 1


