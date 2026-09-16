
import asyncio
import time
import httpx

async def sse_client():
    print("SSE Client: connecting...")
    async with httpx.AsyncClient() as client:
        async with client.stream("GET", "http://localhost:3000/api/collector/events/live") as response:
            print("SSE Client: connected.")
            start = time.time()
            async for line in response.aiter_lines():
                if time.time() - start > 5:
                    break
    print("SSE Client: finished.")

async def health_check():
    print("Health Check: waiting 1s...")
    await asyncio.sleep(1)
    print("Health Check: pinging /api/collector/health...")
    async with httpx.AsyncClient() as client:
        start = time.time()
        response = await client.get("http://localhost:3000/api/collector/health")
        duration = time.time() - start
        print(f"Health Check: {response.status_code} in {duration:.3f}s")
        if duration > 1.0:
            print("FAIL: Event loop blocked!")
        else:
            print("PASS: Event loop responsive!")

async def main():
    await asyncio.gather(sse_client(), health_check())

if __name__ == "__main__":
    asyncio.run(main())

