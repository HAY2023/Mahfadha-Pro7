"""
Token-bucket rate limiter with burst support.
"""

import time
import threading


class RateLimiter:
    def __init__(self, rate: float = 60.0, burst: int = 10):
        """
        Args:
            rate:  max requests per second
            burst: max burst tokens
        """
        self.rate = rate
        self.burst = burst
        self._tokens = float(burst)
        self._max_tokens = float(burst)
        self._last_refill = time.monotonic()
        self._lock = threading.Lock()

    def _refill(self):
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self._max_tokens, self._tokens + elapsed * self.rate)
        self._last_refill = now

    def acquire(self, timeout: float = 30.0) -> bool:
        deadline = time.monotonic() + timeout
        while True:
            with self._lock:
                self._refill()
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return True
            if time.monotonic() >= deadline:
                return False
            sleep_time = max(0.01, 1.0 / self.rate)
            time.sleep(sleep_time)

    def wait(self):
        self.acquire(timeout=60.0)

    @property
    def available_tokens(self) -> float:
        with self._lock:
            self._refill()
            return self._tokens
