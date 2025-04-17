import hashlib
import base64
import secrets
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Protocol, TypeVar, AsyncIterator, Iterator, cast

import asyncio
import aiohttp
from Crypto.Cipher import AES

try:
    import orjson as json_lib
except ImportError:
    try:
        import ujson as json_lib
    except ImportError:
        import json as json_lib


class DehashedAPIError(Exception):
    """Exception raised for DeHashed API errors."""
    def __init__(self, message: str, status_code: Optional[int] = None):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)


@dataclass
class SearchParams:
    """Parameters for a DeHashed search query."""
    search_type: str
    query: str
    page: int = 1
    regex: bool = False
    wildcard: bool = False
    deduplicate: bool = True

@dataclass
class RequestConfig:
    """Configuration for an API request."""
    url: str
    method: str
    headers: Dict[str, str]
    payload: Dict[str, Any]


@dataclass
class DehashedResult:
    """Represents a single result from DeHashed API."""
    id: str
    primary_field: str
    email: List[str] = field(default_factory=list)
    name: List[str] = field(default_factory=list)
    address: List[str] = field(default_factory=list)
    phone: List[str] = field(default_factory=list)
    company: List[str] = field(default_factory=list)
    url: List[str] = field(default_factory=list)
    database_name: str = ""
    hashed_password: List[str] = field(default_factory=list)


@dataclass
class SearchResponse:
    """Response from a DeHashed search query."""
    assets_searched: int
    data_wells: int
    total_results: int
    next_page: bool
    elapsed_time: int
    results: List[DehashedResult]
    has_access: bool


class SyncHTTPClient(Protocol):
    """Protocol defining the interface for synchronous HTTP clients."""
    
    def request(self, method: str, url: str, headers: Dict[str, str], json: Dict[str, Any]) -> Any:
        ...
    
    def post(self, url: str, headers: Dict[str, str], json: Dict[str, Any]) -> Any:
        ...


class AsyncHTTPClient(Protocol):
    """Protocol defining the interface for asynchronous HTTP clients."""
    
    async def request(self, method: str, url: str, headers: Dict[str, str], json: Dict[str, Any]) -> Any:
        ...
    
    async def post(self, url: str, headers: Dict[str, str], json: Dict[str, Any]) -> Any:
        ...


class RateLimiter:
    """Handles rate limiting for the DeHashed API."""
    
    def __init__(self) -> None:
        self.limit = 50
        self.remaining = 50
        self.reset = 3
        self.reset_at: Optional[datetime] = None
        self.lock = asyncio.Lock()

    def update_from_headers(self, headers: Dict[str, str]) -> None:
        """Update rate limit information from response headers."""
        if 'x-ratelimit-limit' in headers:
            self.limit = int(headers['x-ratelimit-limit'])
        if 'x-ratelimit-remaining' in headers:
            self.remaining = int(headers['x-ratelimit-remaining'])
        if 'x-ratelimit-reset' in headers:
            self.reset = int(headers['x-ratelimit-reset'])
            self.reset_at = datetime.now() + timedelta(seconds=self.reset)

    def wait_if_needed_sync(self) -> None:
        """Blocking wait if rate limited."""
        if self.remaining <= 0:
            now = datetime.now()
            if self.reset_at and now < self.reset_at:
                wait_time = (self.reset_at - now).total_seconds()
                time.sleep(wait_time + 1)
                self.remaining = self.limit
        
        self.remaining -= 1

    async def wait_if_needed(self) -> None:
        """Async wait if rate limited."""
        async with self.lock:
            if self.remaining <= 0:
                now = datetime.now()
                if self.reset_at and now < self.reset_at:
                    wait_time = (self.reset_at - now).total_seconds()
                    await asyncio.sleep(wait_time + 1)
                    self.remaining = self.limit
            
            self.remaining -= 1


T = TypeVar('T') # Generic type for the HTTP client


class DehashedClient:
    """Client for the Unofficial DeHashed API."""
    
    def __init__(self, auth_token: str, base_url: str = "https://web-api.dehashed.com") -> None:
        """
        Initialise the client.
        
        Args:
            auth_token: The authentication token for your DeHashed Account
            base_url: The base URL for the DeHashed Web-API
        """
        self.auth_token = auth_token
        self.base_url = base_url
        self.rate_limiter = RateLimiter()
        self.default_headers = {
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
            "Authorization": f"Bearer {self.auth_token}",
            "Cache-Control": "no-cache",
            "Content-Type": "application/json",
            "Origin": "https://app.dehashed.com",
            "Pragma": "no-cache",
            "Priority": "u=1, i",
            "Referer": "https://app.dehashed.com/",
            "Sec-Ch-Ua": '"Google Chrome";v="135", "Not-A.Brand";v="8", "Chromium";v="135"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Windows"',
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-site",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36"
        }
        self._session: Optional[aiohttp.ClientSession] = None
    
    def generate_random_hex(self, length: int) -> str:
        """
        Generate a random hex string
        
        Args:
            length: The length of the hex string to generate
            
        Returns:
            A random hex string of specified length
        """
        byte_length = length // 2
        random_bytes = secrets.token_bytes(byte_length)
        return random_bytes.hex()
    
    def reverse_string(self, s: str) -> str:
        """Reverse a string."""
        return s[::-1]
    
    def create_sha256_hash(self, s: str | bytes) -> str:
        """
        Create a SHA-256 hash of a string or bytes.
        
        Args:
            s: The string or bytes to hash
            
        Returns:
            Hex encoded SHA-256 hash
        """
        if isinstance(s, str):
            s = s.encode('utf-8')
        hash_obj = hashlib.sha256(s)
        return hash_obj.hexdigest()
    
    def aes_gcm_encrypt(self, plaintext: str, key: str, iv: str) -> str:
        """
        Encrypt string using AES-GCM
        
        Args:
            plaintext: The string to encrypt
            key: The encryption key
            iv: The initialisation vector
            
        Returns:
            Base64 encoded ciphertext
        """
        key_bytes = key.encode('utf-8')
        iv_bytes = iv.encode('utf-8')
        plaintext_bytes = plaintext.encode('utf-8')
        
        # Adjust key size to 32 bytes (256 bits)
        if len(key_bytes) < 32:
            key_bytes = key_bytes.ljust(32, b'\0')
        elif len(key_bytes) > 32:
            key_bytes = key_bytes[:32]
        
        cipher = AES.new(key_bytes, AES.MODE_GCM, iv_bytes)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext_bytes)
        
        # Combine ciphertext and tag and encode to base64
        combined = ciphertext + tag
        return base64.b64encode(combined).decode('utf-8')
    
    def encrypt_with_auth_token(self, s: str) -> str:
        """
        Encrypt string using your auth token
        
        Args:
            s: The string to encrypt
            
        Returns:
            Encrypted string
        """
        n = self.auth_token[:16]  # IV from first 16 chars of the token
        a = self.auth_token[:32]  # Key from first 32 chars of the token 
        return self.aes_gcm_encrypt(s, a, n)
     
    def generate_search_payload(self, params: SearchParams) -> Dict[str, Any]:
        """
        Create a search payload for the DeHashed Web API.
        
        Args:
            params: Search parameters
            
        Returns:
            Payload dictionary for the search request
        """
        try:            
            # encrypt the search query (r0)
            encrypted_query = self.encrypt_with_auth_token(params.query)
            
            # create a sha 256 hash of the encrypted query string (not bytes)
            to_quit = self.create_sha256_hash(encrypted_query)
            
            # generate random 32-character hex for r2 component
            picked_the_wrong_week = self.generate_random_hex(32)
            
            # reverse the random hex for the third part of r2
            sniffing_glue = self.reverse_string(picked_the_wrong_week)
            
            # Sure is quiet out there
            looks_like_i = picked_the_wrong_week + to_quit + sniffing_glue
            
            # encrypt the search type (r1)
            encrypted_search_type = self.encrypt_with_auth_token(params.search_type)
            
            payload = {
                "r0": encrypted_query,
                "page": params.page,
                "r2": looks_like_i,
                "r1": encrypted_search_type,
                "regex": params.regex,
                "wildcard": params.wildcard,
                "deduplicate": params.deduplicate
            }
            
            return payload
        except Exception as e:
            raise DehashedAPIError(f"Error generating search payload: {e}")
    
    def generate_search_request(self, params: SearchParams, custom_headers: Optional[Dict[str, str]] = None) -> RequestConfig:
        """
        Generate a complete search request object that can be sent to the API.
        
        Args:
            params: Search parameters
            custom_headers: Optional custom headers to include in the request (Overrides default headers)
            
        Returns:
            Request object with URL, method, headers, and payload
        """
        payload = self.generate_search_payload(params)
        
        headers = self.default_headers.copy()
        if custom_headers:
            headers.update(custom_headers)
        
        request = RequestConfig(
            url=f"{self.base_url}/search",
            method="POST",
            headers=headers,
            payload=payload
        )
        
        return request

    def _parse_search_response(self, data: Dict[str, Any]) -> SearchResponse:
        """Parse API response into a SearchResponse object."""
        results = []
        for item in data.get('results', []):
            result = DehashedResult(
                id=item.get('id', ''),
                primary_field=item.get('primary_field', ''),
                email=item.get('email', []),
                name=item.get('name', []),
                address=item.get('address', []),
                phone=item.get('phone', []),
                company=item.get('company', []),
                url=item.get('url', []),
                database_name=item.get('database_name', ''),
                hashed_password=item.get('hashed_password', [])
            )
            results.append(result)
        
        return SearchResponse(
            assets_searched=data.get('assets_searched', 0),
            data_wells=data.get('data_wells', 0),
            total_results=data.get('total_results', 0),
            next_page=data.get('next_page', False),
            elapsed_time=data.get('elapsed_time', 0),
            results=results,
            has_access=data.get('has_access', False)
        )

    def execute_request(self, request: RequestConfig, http_client: Optional[SyncHTTPClient] = None) -> Dict[str, Any]:
        """
        Execute a request synchronously using the users HTTP client
        
        Args:
            request: The request configuration
            http_client: Optional HTTP client to use
            
        Returns:
            The response from the API
        """
        import requests
        
        self.rate_limiter.wait_if_needed_sync()
        
        client = http_client or requests
        
        match request.method.lower():
            case "post":
                if hasattr(client, 'request'):
                    response = client.request(
                        method=request.method,
                        url=request.url,
                        headers=request.headers,
                        json=request.payload
                    )
                else:
                    response = client.post(
                        url=request.url,
                        headers=request.headers,
                        json=request.payload
                    )
            case _:
                raise DehashedAPIError(f"Unsupported method: {request.method}")
                
        self.rate_limiter.update_from_headers(response.headers)
        
        if hasattr(response, 'json'):
            data = response.json()
        elif hasattr(response, 'text'): # why do you return text if you have json?
            data = json_lib.loads(response.text)
        else:
            data = response
        
        if hasattr(response, 'status_code') and response.status_code != 200:
            error_msg = data.get('message', f"Error: {response.status_code}")
            raise DehashedAPIError(error_msg, response.status_code)
        
        return data
    
    def search(
        self, 
        search_type: str, 
        query: str, 
        page: int = 1, 
        regex: bool = False, 
        wildcard: bool = False, 
        deduplicate: bool = True, 
        custom_headers: Optional[Dict[str, str]] = None,
        http_client: Optional[SyncHTTPClient] = None, 
        as_object: bool = False
    ) -> Dict[str, Any] | SearchResponse:
        """
        Perform a search with the DeHashed Web API.
        
        Args:
            search_type: Type of search (email, username, ip_address, domain etc.)
            query: Search query
            page: Page number
            regex: Whether to use regex when searching
            wildcard: Whether to use wildcard in the search
            deduplicate: Whether to let DeHashed deduplicate the results
            custom_headers: Custom headers
            http_client: HTTP client
            as_object: Return data as a SearchResponse object instead of dict
            
        Returns:
            Search results as dict or SearchResponse object if as_object is true
        """
        params = SearchParams(
            search_type=search_type,
            query=query,
            page=page,
            regex=regex,
            wildcard=wildcard,
            deduplicate=deduplicate
        )
        
        request = self.generate_search_request(params, custom_headers)
        data = self.execute_request(request, http_client)
        
        if as_object:
            return self._parse_search_response(data)
        return data
    
    def paginate_search(
        self,
        search_type: str,
        query: str,
        max_pages: int = 10,
        regex: bool = False,
        wildcard: bool = False,
        deduplicate: bool = True,
        custom_headers: Optional[Dict[str, str]] = None,
        http_client: Optional[SyncHTTPClient] = None
    ) -> Iterator[DehashedResult]:
        """
        Perform a paginated search and yield results.
        The Web-API only supports up to a maximum of 499 pages. If you need more than that, I suggest you support DeHashed by using their official API.
        
        Args:
            search_type: Type of search (email, username, ip_address, etc.)
            query: Search query
            max_pages: Maximum number of pages to retrieve
            regex: Whether to use regex when searching
            wildcard: Whether to use wildcard in the search
            deduplicate: Whether to let DeHashed deduplicate the results
            custom_headers: Custom headers
            http_client: HTTP client
            
        Yields:
            Individual DehashedResult objects
        """
        page = 1
        while page <= max_pages:
            response = cast(SearchResponse, self.search(
                search_type=search_type,
                query=query,
                page=page,
                regex=regex,
                wildcard=wildcard,
                deduplicate=deduplicate,
                custom_headers=custom_headers,
                http_client=http_client,
                as_object=True
            ))
            
            if not response.results:
                break
                
            for result in response.results:
                yield result
                
            if not response.next_page:
                break
                
            page += 1

    @asynccontextmanager
    async def session(self) -> AsyncIterator[aiohttp.ClientSession]:
        """
        Context manager for an aiohttp ClientSession.
        
        Yields:
            An aiohttp ClientSession
        """
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(limit=10, ssl=False)
            )
        
        try:
            yield self._session
        finally:
            # Only close if we re exiting the context
            # Don't close here to allow connection pooling
            pass
            
    async def close(self) -> None:
        """Close the client session."""
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None

    async def execute_request_async(
        self, 
        request: RequestConfig, 
        http_client: Optional[AsyncHTTPClient | aiohttp.ClientSession] = None
    ) -> Dict[str, Any]:
        """
        Execute a request asynchronously using the users HTTP client or aiohttp.
        
        Args:
            request: The request configuration
            http_client: Optional async HTTP client to use
            
        Returns:
            The response from the API
        """
        await self.rate_limiter.wait_if_needed()
        
        if http_client:
            match request.method.lower():
                case "post":
                    if hasattr(http_client, 'request'):
                        response = await http_client.request(
                            method=request.method,
                            url=request.url,
                            headers=request.headers,
                            json=request.payload
                        )
                    else:
                        response = await http_client.post(
                            url=request.url,
                            headers=request.headers,
                            json=request.payload
                        )
                case _:
                    raise DehashedAPIError(f"Unsupported method: {request.method}")
                    
            headers = getattr(response, 'headers', {})
            self.rate_limiter.update_from_headers(headers)
            
            if hasattr(response, 'text'):
                text = await response.text()
                try:
                    data = json_lib.loads(text)
                except (ValueError, TypeError) as e:
                    raise DehashedAPIError(f"Failed to parse response: {str(e)}")
            elif hasattr(response, 'json'):
                try:
                    data = await response.json()
                except (ValueError, TypeError, aiohttp.ContentTypeError) as e:
                    raise DehashedAPIError(f"Failed to parse response: {str(e)}")
            else:
                data = response
                
            status = getattr(response, 'status', None)
            if status and status != 200:
                error_msg = data.get('message', f"Error: {status}")
                raise DehashedAPIError(error_msg, status)
                
            return data
        
        async with self.session() as session:
            async with session.request(
                method=request.method,
                url=request.url,
                headers=request.headers,
                json=request.payload
            ) as response:
                self.rate_limiter.update_from_headers(response.headers)
                
                # get the response as text, then parse as json regardless of content type
                # this should be fine as long as the response is valid JSON
                text = await response.text()
                
                if response.status != 200:
                    try:
                        data = json_lib.loads(text)
                        error_msg = data.get('message', f"Error: {response.status}")
                    except (ValueError, TypeError) as json_error:
                        error_msg = f"Error: {response.status}, Response: {text[:200]}, Parse error: {json_error}"
                    raise DehashedAPIError(error_msg, response.status)
                
                try:
                    return json_lib.loads(text)
                except (ValueError, TypeError) as e:
                    raise DehashedAPIError(
                        f"Failed to parse response as JSON. Content-Type: {response.headers.get('Content-Type')}, "
                        f"Response: {text[:200]}..., Parse error: {e}", 
                        response.status
                    )
    
    async def search_async(
        self,
        search_type: str,
        query: str,
        page: int = 1, 
        regex: bool = False,
        wildcard: bool = False, 
        deduplicate: bool = True,
        custom_headers: Optional[Dict[str, str]] = None,
        http_client: Optional[AsyncHTTPClient | aiohttp.ClientSession] = None,
        as_object: bool = False
    ) -> Dict[str, Any] | SearchResponse:
        """
        Perform an async search on the DeHashed Web API.
        
        Args:
            search_type: Type of search (email, username, ip_address, domain etc.)
            query: Search query
            page: Page number
            regex: Whether to use regex
            wildcard: Whether to use wildcard
            deduplicate: Whether to deduplicate results
            custom_headers: Optional custom headers
            http_client: Optional async HTTP client
            as_object: Return data as a SearchResponse object instead of dict
            
        Returns:
            The search results
        """
        params = SearchParams(
            search_type=search_type,
            query=query,
            page=page,
            regex=regex,
            wildcard=wildcard,
            deduplicate=deduplicate
        )
        
        request = self.generate_search_request(params, custom_headers)
        data = await self.execute_request_async(request, http_client)
        
        if as_object:
            return self._parse_search_response(data)
        return data
        
    async def paginate_search_async(
        self,
        search_type: str,
        query: str,
        max_pages: int = 10,
        regex: bool = False,
        wildcard: bool = False,
        deduplicate: bool = True,
        custom_headers: Optional[Dict[str, str]] = None,
        http_client: Optional[AsyncHTTPClient | aiohttp.ClientSession] = None
    ) -> AsyncIterator[DehashedResult]:
        """
        Perform an async paginated search and yield results.
        
        Args:
            search_type: Type of search (email, username, ip_address, domain etc.)
            query: Search query
            max_pages: Maximum number of pages to retrieve
            regex: Whether to use regex when searching
            wildcard: Whether to use wildcard in the search
            deduplicate: Whether to let DeHashed deduplicate the results
            custom_headers: Custom headers
            http_client: HTTP client
            
        Yields:
            Individual DehashedResult objects
        """
        page = 1
        while page <= max_pages:
            response = cast(SearchResponse, await self.search_async(
                search_type=search_type,
                query=query,
                page=page,
                regex=regex,
                wildcard=wildcard,
                deduplicate=deduplicate,
                custom_headers=custom_headers,
                http_client=http_client,
                as_object=True
            ))
            
            if not response.results:
                break
                
            for result in response.results:
                yield result
                
            if not response.next_page:
                break
                
            page += 1
    
    async def get_all_results_async(
        self,
        search_type: str,
        query: str,
        max_pages: int = 10,
        regex: bool = False,
        wildcard: bool = False,
        deduplicate: bool = True,
        custom_headers: Optional[Dict[str, str]] = None,
        http_client: Optional[AsyncHTTPClient | aiohttp.ClientSession] = None
    ) -> List[DehashedResult]:
        """
        Get all results from a paginated search.
        
        Args:
            search_type: Type of search (email, username, ip_address, domain etc.)
            query: Search query
            max_pages: Maximum number of pages to retrieve
            regex: Whether to use regex when searching
            wildcard: Whether to use wildcard in the search
            deduplicate: Whether to let DeHashed deduplicate the results
            custom_headers: Custom headers
            http_client: HTTP client
            
        Returns:
            A list of all DehashedResult objects
        """
        results = []
        async for result in self.paginate_search_async(
            search_type=search_type,
            query=query,
            max_pages=max_pages,
            regex=regex,
            wildcard=wildcard,
            deduplicate=deduplicate,
            custom_headers=custom_headers,
            http_client=http_client
        ):
            results.append(result)
        return results
    
    def get_all_results(
        self,
        search_type: str,
        query: str,
        max_pages: int = 10,
        regex: bool = False,
        wildcard: bool = False,
        deduplicate: bool = True,
        custom_headers: Optional[Dict[str, str]] = None,
        http_client: Optional[SyncHTTPClient] = None
    ) -> List[DehashedResult]:
        """
        Get all results from a paginated search synchronously.
        
        Args:
            search_type: Type of search (email, username, ip_address, etc.)
            query: Search query
            max_pages: Maximum number of pages to retrieve
            regex: Whether to use regex when searching
            wildcard: Whether to use wildcard in the search
            deduplicate: Whether to let DeHashed deduplicate the results
            custom_headers: Custom headers
            http_client: HTTP client
            
        Returns:
            A list of all DehashedResult objects
        """
        return list(self.paginate_search(
            search_type=search_type,
            query=query,
            max_pages=max_pages,
            regex=regex,
            wildcard=wildcard,
            deduplicate=deduplicate,
            custom_headers=custom_headers,
            http_client=http_client
        ))