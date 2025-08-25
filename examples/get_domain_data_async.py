import asyncio
import json
import os 
import sys 
import time
from dehashed_api import AsyncClient, SearchType
from dehashed_api.auth import login

USERNAME = os.environ.get("DEHASHED_USERNAME")
PASSWORD = os.environ.get("DEHASHED_PASSWORD")

DOMAIN = "example.com"
OUTPUT_FILE = "example.json"

async def main():
    if USERNAME and PASSWORD:
        print("Logging in with username/password...")
        auth_token, refresh_token = await login(
            username=USERNAME,
            password=PASSWORD
        )
        print("Login successful!")
        client = AsyncClient(auth_token=auth_token)
    else:
        print("Error: Please provide both DEHASHED_USERNAME and DEHASHED_PASSWORD")
        return
    
    all_results = []
    start_time = time.time()
    
    try:
        print("Starting search...")
        
        async for result in client.paginate_search_async(
            search_type=SearchType.domain, # or 'domain'
            query=DOMAIN,
            max_pages=5,         # You can increase up to 499 - 20 results per page
            as_object=False      # Get raw JSON format for export
        ):            
            all_results.append(result)
            
            elapsed = time.time() - start_time
            sys.stdout.write(f"\rFetched {len(all_results)} results in {elapsed:.1f} seconds ({len(all_results)/elapsed:.2f} results/sec)...")
            sys.stdout.flush()
            
        print()
        total_time = time.time() - start_time
        
        print(f"Search completed in {total_time:.1f} seconds ({len(all_results)/total_time:.2f} results/sec average)")
        print(f"Writing results to {OUTPUT_FILE}...")
        
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            json.dump(all_results, f, indent=None)
        
        print(f"Saved {len(all_results)} results to {OUTPUT_FILE}")
    
    except Exception as e:
        print(f"\nError during search: {e}")
        raise
    
    finally:
        print("Closing client connection...")
        await client.close()
        print("Done!")

if __name__ == "__main__":
    asyncio.run(main())