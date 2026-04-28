"""
blocker.py — iptables DROP rule management + ban state tracking.

On ban:
  - Insert: iptables -I INPUT -s <ip> -j DROP
  - Record ban in state["banned"] with offense count and scheduled unban time.
  - Notify via Slack (via notifier).
  - Write audit log entry.

Ban durations (backoff schedule, from config):
  offense 1 -> 10 min
  offense 2 -> 30 min
  offense 3 -> 2 hours
  offense 4+ -> permanent (-1)
"""
import subprocess
import time
import logging
import threading

from notifier import Notifier

log = logging.getLogger("blocker")


def _iptables(action: str, ip: str) -> bool:
    """
    Run an iptables command. Returns True on success.
    action: "-I" to insert (ban), "-D" to delete (unban).
    """
    cmd = ["iptables", action, "INPUT", "-s", ip, "-j", "DROP"]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0:
            log.error(f"iptables {action} {ip} failed: {result.stderr.strip()}")
            return False
        return True
    except Exception as e:
        log.error(f"iptables exception for {ip}: {e}")
        return False


class Blocker:
    def __init__(self, cfg, state):
        self.cfg = cfg
        self.state = state
        self.schedule = cfg["ban"]["schedule"]    # [600, 1800, 7200, -1]
        self.notifier = Notifier(cfg)
        self.audit_log = cfg.get("audit_log", "/app/audit.log")
        self._lock = threading.Lock()

    def _duration_for(self, offense_count: int) -> int:
        """
        Return ban duration in seconds for the nth offense.
        -1 means permanent.
        """
        idx = min(offense_count - 1, len(self.schedule) - 1)
        return self.schedule[idx]

    def ban(self, ip: str, condition: str, rate: float, baseline: float) -> None:
        """Ban an IP: iptables DROP + state update + Slack + audit log."""
        with self._lock:
            existing = self.state["banned"].get(ip, {})
            offense = existing.get("offense_count", 0) + 1
            duration = self._duration_for(offense)

            until = (time.time() + duration) if duration != -1 else -1

            self.state["banned"][ip] = {
                "offense_count": offense,
                "until": until,
                "duration": duration,
                "condition": condition,
                "banned_at": time.time(),
            }

        success = _iptables("-I", ip)
        if not success:
            log.error(f"Failed to ban {ip} via iptables")

        # Slack alert
        self.notifier.ban_alert(ip, condition, rate, baseline, duration, offense)

        # Audit log
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        dur_str = f"{duration}s" if duration != -1 else "permanent"
        entry = (
            f"[{ts}] BAN ip={ip} | condition={condition} | "
            f"rate={rate:.4f} | baseline={baseline:.4f} | "
            f"duration={dur_str} | offense={offense}\n"
        )
        log.info(entry.strip())
        with open(self.audit_log, "a") as f:
            f.write(entry)

    def unban(self, ip: str) -> None:
        """Remove iptables rule and clear from state."""
        _iptables("-D", ip)
        with self._lock:
            self.state["banned"].pop(ip, None)

        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        entry = f"[{ts}] UNBAN ip={ip}\n"
        log.info(entry.strip())
        with open(self.audit_log, "a") as f:
            f.write(entry)
