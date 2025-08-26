import asyncio
import logging
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Dict, Optional, cast

from ._core import (
    DehashedAPIError,
    RateLimiterState,
    build_search_payload,
    parse_search_response,
)
from .types import RequestConfig, SearchParams, SearchResponse, DehashedResult, SearchType


class AsyncClient:
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
        self._auth_lock = asyncio.Lock()
        self._session: Optional[Any] = None
        self._logger = logging.getLogger(__name__)

        self.default_headers = {
            "Accept": "*/*",
            "Content-Type": "application/json",
            "Referer": "https://app.dehashed.com/",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
        }

        if self.username and self.password and self.save_cookie and self.state_key:
            self._load_session()

    def _load_session(self) -> None:
        if not self.state_key:
            return
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
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

    async def _save_session_async(self) -> None:
        if self.save_cookie and self.state_key and self.refresh_token and self.auth_token:
            try:
                import aiofiles
            except ImportError:
                raise ImportError("aiofiles is required for async session persistence. Install with: pip install aiofiles")
            import base64
            try:
                async with aiofiles.open(".cookie", "w") as f:
                    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                    import secrets
                    nonce = secrets.token_bytes(12)
                    cipher = AESGCM(self.state_key.encode("utf-8"))
                    session_data = f"{self.refresh_token}|{self.auth_token}".encode("utf-8")
                    ct = cipher.encrypt(nonce, session_data, None)
                    await f.write(base64.b64encode(nonce + ct).decode("utf-8"))
            except Exception:
                pass

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

    async def _login_async(self) -> None:
        from .auth import login
        if not self.username or not self.password:
            raise DehashedAPIError("Username and password required for login")
        try:
            self.auth_token, self.refresh_token = await login(
                username=self.username,
                password=self.password,
                state_key=self.state_key if self.save_cookie else None,
            )
        except Exception as e:
            raise DehashedAPIError(f"Login failed: {e}")
        await self._save_session_async()

    async def _refresh_token_async(self) -> None:
        from .auth import refresh_session
        if not self.refresh_token:
            raise DehashedAPIError("No refresh token available")
        try:
            self.auth_token = await refresh_session(
                refresh_token=self.refresh_token,
                state_key=self.state_key if self.save_cookie else None,
            )
        except Exception as e:
            raise DehashedAPIError(f"Token refresh failed: {e}")
        await self._save_session_async()

    async def _ensure_auth_async(self) -> None:
        async with self._auth_lock:
            if not self.auth_token:
                if self.username and self.password:
                    await self._login_async()
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

    @asynccontextmanager
    async def session(self) -> AsyncIterator[Any]:
        try:
            import aiohttp
        except ImportError:
            raise ImportError("aiohttp is required for asynchronous operations. Install with: pip install dehashed-api[async]")
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=self.request_timeout)
            self._session = aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(limit=10),
                timeout=timeout,
            )
        try:
            yield self._session
        finally:
            pass

    async def execute_request_async(self, request: RequestConfig, max_retries: int = 3) -> Dict[str, Any]:
        try:
            import aiohttp
        except ImportError:
            raise ImportError("aiohttp is required for asynchronous operations. Install with: pip install dehashed-api[async]")
        retries = 0
        while retries <= max_retries:
            await self._ensure_auth_async()
            request.headers["Authorization"] = f"Bearer {self.auth_token}"
            self._logger.debug("POST %s", request.url)
            async with self.session() as session:
                async with session.post(
                    url=request.url,
                    headers=request.headers,
                    json=request.payload,
                ) as response:
                    self._logger.debug("POST %s -> %s", request.url, response.status)
                    self.rate.update_from_headers(response.headers)
                    text = await response.text()
                    if response.status == 429:
                        if self.rate.retry_after is not None:
                            backoff_time = self.rate.retry_after
                        else:
                            backoff_time = 40
                        self._logger.warning("429 received; backing off %ss", backoff_time)
                        await asyncio.sleep(backoff_time)
                        self.rate.remaining = self.rate.limit
                        self.rate.retry_after = None
                        continue
                    elif response.status in [401, 403] and self.auto_refresh and retries < max_retries:
                        if self.refresh_token:
                            try:
                                self._logger.info("Refreshing token")
                                await self._refresh_token_async()
                                retries += 1
                                continue
                            except DehashedAPIError:
                                pass
                        if self.username and self.password:
                            try:
                                self._logger.info("Re-logging in")
                                await self._login_async()
                                retries += 1
                                continue
                            except DehashedAPIError:
                                pass
                        try:
                            import orjson as json_lib
                        except Exception:
                            try:
                                import ujson as json_lib  # type: ignore
                            except Exception:
                                import json as json_lib  # type: ignore
                        try:
                            data = json_lib.loads(text)
                            error_msg = data.get('message', f"Authentication failed: {response.status}")
                        except Exception:
                            error_msg = f"Authentication failed: {response.status}"
                        self._logger.error("Auth error: %s", error_msg)
                        raise DehashedAPIError(error_msg, response.status)
                    elif response.status != 200:
                        try:
                            import orjson as json_lib
                        except Exception:
                            try:
                                import ujson as json_lib  # type: ignore
                            except Exception:
                                import json as json_lib  # type: ignore
                        try:
                            data = json_lib.loads(text)
                            error_msg = data.get('message', f"Error: {response.status}")
                        except Exception:
                            error_msg = f"Error: {response.status}, Response: {text[:200]}"
                        self._logger.error("Request error: %s", error_msg)
                        raise DehashedAPIError(error_msg, response.status)
                    try:
                        try:
                            import orjson as json_lib
                        except Exception:
                            try:
                                import ujson as json_lib  # type: ignore
                            except Exception:
                                import json as json_lib  # type: ignore
                        return json_lib.loads(text)
                    except Exception as e:
                        self._logger.error("JSON parse error: %s", e)
                        raise DehashedAPIError(
                            f"Failed to parse response as JSON. Response: {text[:200]}..., Parse error: {e}",
                            response.status,
                        )

    async def search_async(
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
        data = await self.execute_request_async(request)
        if as_object:
            return parse_search_response(data)
        return data

    async def paginate_search_async(
        self,
        search_type: str | SearchType,
        query: str,
        max_pages: int = 10,
        regex: bool = False,
        wildcard: bool = False,
        deduplicate: bool = True,
        custom_headers: Optional[Dict[str, str]] = None,
        as_object: bool = True,
    ) -> AsyncIterator[DehashedResult] | AsyncIterator[Dict[str, Any]]:
        page = 1
        while page <= max_pages:
            self._logger.debug("paginate page=%s", page)
            response = await self.search_async(
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

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None


