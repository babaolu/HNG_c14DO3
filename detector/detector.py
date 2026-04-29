"""
detector.py — Anomaly detection logic.

For every incoming log entry:
  1. Compute z-score: (rate - mean) / stddev
  2. Check rate multiplier: rate > multiplier * mean
  3. Check error surge: ip_error_rate > error_surge_multiplier * baseline_error_mean
     -> error surge tightens its detection thresholds automatically.
  4. Fire IP ban or global Slack alert as appropriate.

All thresholds come from config.yaml. None are hardcoded.
"""
import time
import logging
import threading

from blocker import Blocker
from notifier import Notifier

log = logging.getLogger("detector")


class AnomalyDetector:
    def __init__(self, cfg, state, baseline):
        self.cfg = cfg
        self.state = state
        self.baseline = baseline
        self.blocker = Blocker(cfg, state)
        self.notifier = Notifier(cfg)

        d = cfg["detection"]
        self.zscore_threshold = d["zscore_threshold"]         # 3.0
        self.rate_multiplier = d["rate_multiplier"]           # 5.0
        self.error_surge_mult = d["error_surge_multiplier"]   # 3.0

        # Deduplicate: track recently flagged IPs/globals to avoid
        # sending duplicate alerts within a 30-second window.
        self._recent_flags: dict[str, float] = {}
        self._lock = threading.Lock()

    def _z_score(self, rate: float) -> float:
        """
        Z-score = (observed_rate - mean) / stddev
        Measures how many standard deviations above the baseline we are.
        High z-score = anomalous.
        """
        mean = self.baseline.effective_mean
        stddev = self.baseline.effective_stddev
        if stddev == 0:
            return 0.0
        return (rate - mean) / stddev

    def _is_recent(self, key: str, window: float = 30.0) -> bool:
        """Return True if we already flagged this key within `window` seconds."""
        with self._lock:
            last = self._recent_flags.get(key, 0.0)
            if time.time() - last < window:
                return True
            self._recent_flags[key] = time.time()
            return False

    def evaluate(
        self,
        ip: str,
        ip_rate: float,
        global_rate: float,
        ip_error_rate: float,
        entry: dict,
    ) -> None:
        """
        Called for every log line. Evaluate IP and global anomalies.
        """
        mean = self.baseline.effective_mean
        stddev = self.baseline.effective_stddev
        error_mean = self.baseline.effective_error_mean

        # --- Error Surge Check ---
        # If the IP's error rate is >= 3x the baseline error rate,
        # tighten its detection thresholds automatically.
        in_error_surge = (
            error_mean > 0 and
            ip_error_rate >= self.error_surge_mult * error_mean
        )
        if in_error_surge:
            effective_zscore_thresh = self.zscore_threshold / 2.0
            effective_rate_mult = self.rate_multiplier / 2.0
            log.debug(f"Error surge on {ip}: tightened thresholds")
        else:
            effective_zscore_thresh = self.zscore_threshold
            effective_rate_mult = self.rate_multiplier

        # --- Per-IP Anomaly ---
        if ip and ip not in self.state.get("banned", {}):
            ip_zscore = self._z_score(ip_rate)
            ip_rate_check = (mean > 0 and ip_rate >= effective_rate_mult * mean)
            ip_zscore_check = ip_zscore >= effective_zscore_thresh

            if (ip_rate_check or ip_zscore_check) and not self._is_recent(f"ip:{ip}"):
                condition = (
                    f"zscore={ip_zscore:.2f}>={effective_zscore_thresh}"
                    if ip_zscore_check
                    else f"rate={ip_rate:.2f}>={effective_rate_mult}x mean={mean:.4f}"
                )
                log.warning(
                    f"IP ANOMALY {ip}: {condition} "
                    f"(error_surge={in_error_surge})"
                )
                min_rate = self.cfg["ban"].get("min_rate_to_ban", 5.0)
                if ip_rate >= min_rate:                          # only ban if rate is high enough
                    self.blocker.ban(ip, condition, ip_rate, mean)
                else:
                    log.debug(
                        f"Rate {ip_rate:.2f} below min_rate_to_ban {min_rate}, "
                        f"logging anomaly but skipping ban"
                    )
        # --- Global Anomaly ---
        global_zscore = self._z_score(global_rate)
        global_rate_check = (mean > 0 and global_rate >= self.rate_multiplier * mean)
        global_zscore_check = global_zscore >= self.zscore_threshold

        if (global_rate_check or global_zscore_check) and not self._is_recent("global"):
            condition = (
                f"zscore={global_zscore:.2f}>={self.zscore_threshold}"
                if global_zscore_check
                else f"rate={global_rate:.2f}>={self.rate_multiplier}x mean={mean:.4f}"
            )
            log.warning(f"GLOBAL ANOMALY: {condition}")
            self.notifier.global_alert(condition, global_rate, mean)
