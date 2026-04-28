"""
baseline.py — Rolling 30-minute baseline for global requests-per-second.

How it works:
  - Every second we record how many requests arrived in that second.
  - We keep per-hour slots (slot index = unix_hour % 24).
  - Every 60 seconds we recalculate effective_mean and effective_stddev from:
      1. The current hour slot if it has >= 120 data points (2 min of data).
      2. Otherwise fall back to the full 30-min deque.
  - We apply floor values so stddev never reaches zero (avoids division by zero
    in the z-score formula).
"""
import time
import math
import logging
import threading
from collections import deque

log = logging.getLogger("baseline")

# Minimum points in a slot before we trust it
MIN_SLOT_POINTS = 120


class BaselineTracker:
    def __init__(self, cfg):
        b = cfg["baseline"]
        self.window_sec = b["window_seconds"]       # 1800 (30 min)
        self.recalc_interval = b["recalc_interval"]  # 60 s
        self.floor_mean = b["floor_mean"]
        self.floor_stddev = b["floor_stddev"]

        # Rolling deque: each entry is (timestamp, count_in_that_second)
        # We evict entries older than window_sec during recalculation.
        self._rolling: deque = deque()

        # Per-hour slots: list of 24 deques, indexed by (unix_hour % 24)
        # Each slot stores per-second counts for that hour of the day.
        self._hour_slots: list[deque] = [deque() for _ in range(24)]

        # Current per-second bucket
        self._bucket_start: float = time.time()
        self._bucket_count: int = 0
        self._lock = threading.Lock()

        # Published values (read by detector)
        self.effective_mean: float = self.floor_mean
        self.effective_stddev: float = self.floor_stddev

        # Error rate baseline (fraction of requests that are 4xx/5xx)
        self._error_rolling: deque = deque()
        self._error_bucket: int = 0
        self.effective_error_mean: float = 0.05

        # Audit log path
        self.audit_log = cfg.get("audit_log", "/app/audit.log")

    def record(self, is_error: bool = False) -> None:
        """Called by monitor for every parsed log line."""
        with self._lock:
            self._bucket_count += 1
            if is_error:
                self._error_bucket += 1

    def _flush_bucket(self) -> None:
        """Commit the current per-second bucket into the rolling deque."""
        now = time.time()
        count = self._bucket_count
        err_count = self._error_bucket
        self._bucket_count = 0
        self._error_bucket = 0
        self._bucket_start = now

        hour_slot = int(now // 3600) % 24

        self._rolling.append((now, count))
        self._hour_slots[hour_slot].append((now, count))
        self._error_rolling.append((now, err_count))

    def _evict_old(self, now: float) -> None:
        """Remove entries from rolling deque older than window_sec."""
        cutoff = now - self.window_sec
        while self._rolling and self._rolling[0][0] < cutoff:
            self._rolling.popleft()
        while self._error_rolling and self._error_rolling[0][0] < cutoff:
            self._error_rolling.popleft()

        # Evict each hour slot of entries older than 2 hours
        slot_cutoff = now - 7200
        for slot in self._hour_slots:
            while slot and slot[0][0] < slot_cutoff:
                slot.popleft()

    @staticmethod
    def _mean_stddev(values: list[float]) -> tuple[float, float]:
        """Compute population mean and stddev from a list of floats."""
        n = len(values)
        if n == 0:
            return 0.0, 0.0
        mean = sum(values) / n
        variance = sum((x - mean) ** 2 for x in values) / n
        return mean, math.sqrt(variance)

    def recalculate(self) -> None:
        """
        Recalculate effective_mean and effective_stddev.
        Preference order:
          1. Current hour slot if it has >= MIN_SLOT_POINTS samples.
          2. Rolling 30-minute window.
        Apply floors and write to audit log.
        """
        with self._lock:
            now = time.time()
            self._evict_old(now)

            current_hour_slot = int(now // 3600) % 24
            slot = self._hour_slots[current_hour_slot]

            # Prefer current hour slot if data is sufficient
            if len(slot) >= MIN_SLOT_POINTS:
                counts = [c for (_, c) in slot]
                source = f"hour_slot[{current_hour_slot}]"
            else:
                counts = [c for (_, c) in self._rolling]
                source = "rolling_30min"

            mean, stddev = self._mean_stddev(counts)

            # Apply floors
            self.effective_mean = max(mean, self.floor_mean)
            self.effective_stddev = max(stddev, self.floor_stddev)

            # Error baseline
            if self._error_rolling:
                total = sum(c for (_, c) in self._rolling) or 1
                errs = sum(c for (_, c) in self._error_rolling)
                self.effective_error_mean = errs / total
            else:
                self.effective_error_mean = 0.05

        # Audit log entry
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        entry = (
            f"[{ts}] BASELINE_RECALC ip=global | source={source} | "
            f"mean={self.effective_mean:.4f} | "
            f"stddev={self.effective_stddev:.4f} | "
            f"samples={len(counts)}\n"
        )
        log.info(entry.strip())
        with open(self.audit_log, "a") as f:
            f.write(entry)

    def run(self) -> None:
        """
        Background thread:
          - Flushes a 1-second bucket every second.
          - Recalculates baseline every recalc_interval seconds.
        """
        last_recalc = time.time()
        while True:
            time.sleep(1.0)
            self._flush_bucket()

            now = time.time()
            if now - last_recalc >= self.recalc_interval:
                self.recalculate()
                last_recalc = now
