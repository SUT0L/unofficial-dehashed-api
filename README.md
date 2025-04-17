# Unofficial DeHashed API Client

This is an **unofficial** Python wrapper for interacting with the DeHashed Web-API (not their official API). 
The client handles rate limiting, and provides both synchronous and asynchronous interfaces for you to use.

## ⚠️ Important Notice

This is NOT an official DeHashed client. Please support DeHashed by using their official services:

DeHashed provides a valuable service for security researchers, and they have rate limits in place for a reason. **Please do not abuse their service.**. This library enforces these rate limits client-side to ensure responsible usage and explicitly doesn't implement proxy usage per request. 

**I encourage you to support DeHashed by using their official API** becase sometimes, the official API is just the best option. This library is extremely limited in comparison.

No-- WHOIS lookups are not supported as they require credits on your account.

## Features

- Automatically handles rate limits using the API's response headers
- Full support for async/await patterns
- BYO HTTP client (requests, httpx, aiohttp, etc.)
- Type-hinted dataclasses

## Prerequisites

- A DeHashed subscription is required to use this client
- Understand that you are responsible for your usage of your own DeHashed account.
- Python 3.10+

## Installation

```bash
pip install git+https://github.com/SUT0L/unofficial-dehashed-api.git
```

## Quick Start

```python
from dehashed_api.client import DehashedClient

# Initialise with your auth token
client = DehashedClient(auth_token="your_auth_token_here")

# Perform a basic search
response = client.search(
    search_type="domain", 
    query="example.com", 
    as_object=True # Get results as objects instead of raw JSON
)

# Display results
print(f"Found {response.total_results} results")
for result in response.results:
    print(f"ID: {result.id}, Email: {', '.join(result.email)}")
```

## Asynchronous Usage

```python
import asyncio
from dehashed_api.client import DehashedClient

async def main():
    client = DehashedClient(auth_token="your_auth_token_here")
    
    try:
        response = await client.search_async(
            search_type="domain",
            query="example.com",
            as_object=True
        )
        
        print(f"Found {response.total_results} results")
        for result in response.results:
            print(f"ID: {result.id}, Email: {', '.join(result.email)}")
            
    finally:
        await client.close()

asyncio.run(main())
```

## Paginated Searches

For searches that may return a large number of results, use the pagination methods. The Web-API only supports up to a maximum of 499 pages. If you need more than that, I suggest you support DeHashed by using their official API.

```python
# Synchronous pagination
for result in client.paginate_search(
    search_type="domain",
    query="example.com",
    max_pages=5
):
    print(f"ID: {result.id}, Email: {', '.join(result.email)}")

# Asynchronous pagination
async for result in client.paginate_search_async(
    search_type="domain",
    query="example.com",
    max_pages=5
):
    print(f"ID: {result.id}, Email: {', '.join(result.email)}")
```

## Obtaining an Auth Token

To use this client, you need an authentication token from DeHashed.
I won't provide a method to automatically obtain them, or to refresh them automatically as this helps prevent abuse of DeHashed's service. If you really do need this, you'll know how to implement this functionality.


## Disclaimer

This project is not affiliated with DeHashed in any way. Use at your own risk. The maintainers of this library are not responsible for any misuse or violations of DeHashed's terms of service. Please read [DeHashed's terms of service](https://www.dehashed.com/legal) before using this library.

