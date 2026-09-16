
import asyncio
import json
import uuid
import time
import sys
import redis.asyncio as redis
from datetime import datetime

async def inject_events(rate, duration):
    r = redis.Redis.from_url("redis://localhost:6379")
    print(f"Injecting {rate} events/sec for {duration} seconds...")
    start = time.time()
    events_injected = 0
    
    chunk_time = 0.05
    events_per_chunk = max(1, int(rate * chunk_time))
    
    while time.time() - start < duration:
        chunk_start = time.time()
        for _ in range(events_per_chunk):
            event = {
                "event_type": "command",
                "payload": {
                    "session_id": str(uuid.uuid4())[:8],
                    "timestamp": datetime.utcnow().isoformat(),
                    "attacker_ip": "1.2.3.4",
                    "command": f"test-command-{events_injected}"
                }
            }
            await r.xadd("honeypot:commands", {"data": json.dumps(event)})
            events_injected += 1
            
        elapsed = time.time() - chunk_start
        if elapsed < chunk_time:
            await asyncio.sleep(chunk_time - elapsed)
            
    print(f"Done. Injected {events_injected} events.")

if __name__ == "__main__":
    rate = int(sys.argv[1]) if len(sys.argv) > 1 else 100
    duration = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    asyncio.run(inject_events(rate, duration))

