import time
import threading
import queue
from typing import Callable, Any, Optional, List
from dataclasses import dataclass
from datetime import datetime, timedelta

@dataclass
class RateLimitConfig:
    requests_per_minute: int
    burst_limit: int = 1
    max_retries: int = 2
    base_backoff_seconds: float = 2.0

class RateLimiter:

    def __init__(self, config: RateLimitConfig):
        self.config = config
        self.tokens = config.burst_limit
        self.last_update = time.time()
        self.lock = threading.Lock()
        self._paused_until = 0

    def _refill_tokens(self):
        now = time.time()
        elapsed = now - self.last_update
        refill_rate = self.config.requests_per_minute / 60.0
        self.tokens = min(self.config.burst_limit, self.tokens + elapsed * refill_rate)
        self.last_update = now

    def acquire(self, timeout: float=60.0) -> bool:
        start_time = time.time()
        while True:
            with self.lock:
                self._refill_tokens()
                if self.tokens >= 1:
                    self.tokens -= 1
                    return True
                if self._paused_until > time.time():
                    sleep_time = self._paused_until - time.time()
                else:
                    needed = 1 - self.tokens
                    refill_time = needed / (self.config.requests_per_minute / 60.0)
                    sleep_time = min(refill_time, timeout)
            if time.time() - start_time >= timeout:
                return False
            time.sleep(min(sleep_time, 1.0))

    def pause(self, duration_seconds: float):
        with self.lock:
            self._paused_until = time.time() + duration_seconds

    def reset(self):
        with self.lock:
            self.tokens = self.config.burst_limit
            self._paused_until = 0

class RequestThrottler:

    def __init__(self):
        self.limiters: dict[str, RateLimiter] = {}
        self._active_requests: dict[str, int] = {}
        self.lock = threading.Lock()

    def register_provider(self, provider: str, config: RateLimitConfig):
        self.limiters[provider] = RateLimiter(config)

    def execute_throttled(self, provider: str, func: Callable[[], Any], max_retries: int=2) -> tuple[bool, Any, Optional[str]]:
        if provider not in self.limiters:
            success, result = (True, func())
            return (success, result, None)
        limiter = self.limiters[provider]
        for attempt in range(max_retries + 1):
            try:
                if not limiter.acquire(timeout=30):
                    return (False, None)
                with self.lock:
                    self._active_requests[provider] = self._active_requests.get(provider, 0) + 1
                try:
                    result = func()
                    return (True, result, None)
                finally:
                    with self.lock:
                        self._active_requests[provider] = max(0, self._active_requests.get(provider, 0) - 1)
            except Exception as e:
                error_msg = str(e).lower()
                if '429' in error_msg or 'rate limit' in error_msg:
                    backoff = 2 ** attempt * limiter.config.base_backoff_seconds
                    limiter.pause(backoff)
                    time.sleep(backoff)
                    continue
                if attempt == max_retries:
                    return (False, None, str(e))
                time.sleep(1)
        return (False, None)

    def get_status(self, provider: str) -> dict:
        if provider not in self.limiters:
            return {'registered': False}
        limiter = self.limiters[provider]
        return {'registered': True, 'tokens_available': limiter.tokens, 'paused': limiter._paused_until > time.time(), 'active_requests': self._active_requests.get(provider, 0)}

class LookupQueue:

    def __init__(self, max_size: int=1000):
        self._queue = queue.PriorityQueue(maxsize=max_size)
        self._seen: set[str] = set()
        self._lock = threading.Lock()
        self._counter = 0

    def add(self, ioc_type: str, ioc_value: str, priority: int=5) -> bool:
        key = f'{ioc_type}:{ioc_value}'
        with self._lock:
            if key in self._seen:
                return False
            self._seen.add(key)
            self._counter += 1
            self._queue.put((priority, self._counter, ioc_type, ioc_value))
            return True

    def add_batch(self, iocs: List[tuple], priority: int=5) -> int:
        added = 0
        for ioc_type, ioc_value in iocs:
            if self.add(ioc_type, ioc_value, priority):
                added += 1
        return added

    def get(self, timeout: float=1.0) -> Optional[tuple]:
        try:
            priority, counter, ioc_type, ioc_value = self._queue.get(timeout=timeout)
            return (ioc_type, ioc_value)
        except queue.Empty:
            return None

    def size(self) -> int:
        return self._queue.qsize()

    def clear(self):
        while not self._queue.empty():
            try:
                self._queue.get_nowait()
            except queue.Empty:
                break
        with self._lock:
            self._seen.clear()
