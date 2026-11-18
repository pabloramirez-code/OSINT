import asyncio
import time


class TokenBucket:
    def __init__(self, rate: float, capacity: float | None = None) -> None:
        self.rate = rate
        self.capacity = capacity if capacity is not None else max(1.0, rate)
        self._tokens = self.capacity
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                self._tokens = min(self.capacity, self._tokens + (now - self._updated) * self.rate)
                self._updated = now
                if self._tokens >= 1:
                    self._tokens -= 1
                    return
                await asyncio.sleep((1 - self._tokens) / self.rate)


class RateLimiter:
    """Un token bucket por módulo: `rate` peticiones por segundo."""

    def __init__(self) -> None:
        self._buckets: dict[str, TokenBucket] = {}

    async def acquire(self, name: str, rate: float) -> None:
        bucket = self._buckets.setdefault(name, TokenBucket(rate))
        await bucket.acquire()
