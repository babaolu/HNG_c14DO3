"""
monitor.py — Continuously tail and parse the Nginx JSON access log.
             Maintains two deque-based sliding windows (per-IP and global)
             over the last 60 seconds. Feeds parsed entries to the detector.
"""
import json
import time
import logging
import os
from collections import defaultdict, deque

log = logging.getLogger("monitor")


class LogMonitor:
    def __init__(self, cfg, detector, state):
        self.log_path = cfg["log_path"]
        self.window_sec = cfg["detection"]["window_seconds"]  # 60s
        self.detector = detector
        self.state = state

        # --- Sliding Windows (deque-based) ---
        # Each entry is a float unix timestamp.
        # We evict entries older than window_sec on every append.
        #
        # global_window: deque of timestamps for all requests
        # ip_windows:    defaultdict(deque) — one deque per source IP
        # ip_errors:     defaultdict(deque) — 4xx/5xx timestamps per IP
        self.global_window: deque = deque()
        self.ip_windows: dict[str, deque] = defaultdict(deque)
        self.ip_errors: dict[str, deque] = defaultdict(deque)

    def _evict(self, dq: deque, now: float) -> None:
        """Remove timestamps older than window_sec from the left of the deque."""
        cutoff = now - self.window_sec
        while dq and dq[0] < cutoff:
            dq.popleft()

    def _append_and_evict(self, dq: deque, ts: float, now: float) -> None:
        """Append a timestamp then evict stale entries."""
        dq.append(ts)
        self._evict(dq, now)

    def _parse_line(self, line: str) -> dict | None:
        """Parse one JSON log line. Returns None on failure."""
        line = line.strip()
        if not line:
            return None
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            return None

    def _update_state(self) -> None:
        """Refresh shared dashboard state (top IPs, global rps)."""
        now = time.time()
        self._evict(self.global_window, now)
        global_count = len(self.global_window)
        self.state["global_rps"] = global_count / self.window_sec

        # Top 10 IPs by window count
        ip_counts = {
            ip: len(dq) for ip, dq in self.ip_windows.items()
            if len(dq) > 0
        }
        self.state["top_ips"] = dict(
            sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        )

    def run(self) -> None:
        """Tail the log file indefinitely. Handle log rotation gracefully."""
        log.info(f"Tailing {self.log_path}")
        while not os.path.exists(self.log_path):
            log.warning(f"Waiting for log file: {self.log_path}")
            time.sleep(2)

        with open(self.log_path, "r") as f:
            # Seek to end so we don't replay history on startup
            f.seek(0, 2)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.05)   # brief pause — tight loop on idle
                    self._update_state()
                    continue

                entry = self._parse_line(line)
                if not entry:
                    continue

                ip = entry.get("source_ip", "")
                status = int(entry.get("status", 200))
                now = time.time()

                # --- Update sliding windows ---
                self._append_and_evict(self.global_window, now, now)
                self._append_and_evict(self.ip_windows[ip], now, now)

                if status >= 400:
                    self._append_and_evict(self.ip_errors[ip], now, now)

                # Compute current rates (requests per second within window)
                ip_rate = len(self.ip_windows[ip]) / self.window_sec
                global_rate = len(self.global_window) / self.window_sec
                ip_error_rate = len(self.ip_errors[ip]) / self.window_sec

                # Hand off to detector
                self.detector.evaluate(
                    ip=ip,
                    ip_rate=ip_rate,
                    global_rate=global_rate,
                    ip_error_rate=ip_error_rate,
                    entry=entry,
                )
                log.debug(
                    f"{ip} ip_rps={ip_rate:.2f} "
                    f"global_rps={global_rate:.2f} status={status}"
                )
