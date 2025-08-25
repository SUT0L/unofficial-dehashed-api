# Unofficial DeHashed API Client

This is an **unofficial** Python wrapper for interacting with the DeHashed **Web-API** (not their official API).
The client handles rate limiting, and provides both synchronous and asynchronous interfaces for you to use.

## ⚠️ Important Notice

DeHashed provides a valuable service for security researchers, and they have rate limits in place for a reason.
WHOIS lookups are not supported as they require credits on your account.

## Prerequisites

- A DeHashed subscription is required to use this client
- Understand that you are responsible for your usage of your own DeHashed account.
- Python 3.10+

## Installation

```bash
pip install git+https://github.com/SUT0L/unofficial-dehashed-api.git
```

## Authentication

Two approaches are supported:

- Implicit: pass credentials directly to the client
- Explicit: call `login` to obtain tokens, then pass the token to the client (For IDPs / External secret managers)

```python
# Implicit
from dehashed_api import Client

client = Client(username="your_username", password="your_password")
response = client.search(search_type="domain", query="example.com")
print(response.total_results)
```

```python
# Explicit
import asyncio
from dehashed_api import AsyncClient
from dehashed_api.auth import login

async def main():
    auth_token, refresh_token = await login(
        username="your_username",
        password="your_password"
    )
    client = AsyncClient(auth_token=auth_token)
    try:
        response = await client.search_async(search_type="domain", query="example.com")
        print(f"Found {response.total_results} results")
    finally:
        await client.close()

asyncio.run(main())
```

### Session Persistence
When using username/password authentication, you can enable encrypted session storage by providing a 32-character `state_key`. This will save your session to a `.cookie` file, allowing you to reuse the session across multiple runs without re-authenticating.

```bash
# Generate a random 32-character key for session encryption
openssl rand -base64 32
```

```python
auth_token, refresh_token = await login(
    username="your_username",
    password="your_password",
    state_key=state_key
)
```

## Paginated Searches

For searches that may return a large number of results, use the pagination methods. The Web-API only supports up to a maximum of 499 pages. If you need more than that, I suggest you support DeHashed by using their official API.

```python
# Synchronous pagination
from dehashed_api import Client

client = Client(auth_token="your_auth_token_here")
for result in client.paginate_search(
    search_type="domain",
    query="example.com",
    max_pages=5
):
    print(f"ID: {result.id}, Email: {', '.join(result.email)}")

# Asynchronous pagination
import asyncio
from dehashed_api import AsyncClient

async def main():
    client = AsyncClient(auth_token="your_auth_token_here")
    async for result in client.paginate_search_async(
        search_type="domain",
        query="example.com",
        max_pages=5
    ):
        print(f"ID: {result.id}, Email: {', '.join(result.email)}")

asyncio.run(main())
```

## Complete Example with Authentication

```
pip install git+https://github.com/SUT0L/unofficial-dehashed-api.git
wget https://raw.githubusercontent.com/SUT0L/unofficial-dehashed-api/refs/heads/main/examples/get_domain_data_async.py
python get_domain_data_async.py
```

## Environment Variables

For convenience, you can set these environment variables:

```bash
# Option 1: Direct auth token
export DEHASHED_AUTH_TOKEN="your_auth_token_here"

# Option 2: Username/password with optional session persistence
export DEHASHED_USERNAME="your_username"
export DEHASHED_PASSWORD="your_password"
export DEHASHED_STATE_KEY="your_32_character_encryption_key"  # Optional
```

## Search types

You can pass strings or the `SearchType` enum (e.g., `SearchType.domain`).

## Logging

This library uses Python's `logging` and does not emit logs unless you configure it. The package logger name is `dehashed_api`.

Enable logs:

```python
import logging

logging.basicConfig(level=logging.INFO)
logging.getLogger("dehashed_api").setLevel(logging.DEBUG)
```

Log levels used:
- DEBUG: request start/end (method, URL, status), rate-limit updates, pagination progress
- INFO: retries, token refreshes, login success
- WARNING: 429/backoff events
- ERROR: request failures, JSON parse failures

## Disclaimer

This project is not affiliated with DeHashed in any way. Use at your own risk. The maintainers of this library are not responsible for any misuse or violations of [DeHashed's terms of service](https://www.dehashed.com/legal).

Commercial use available by private agreement.