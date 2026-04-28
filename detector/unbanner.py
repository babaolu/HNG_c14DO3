"""
unbanner.py — Background thread that checks for expired bans every 10 seconds
              and releases them via iptables + Slack notification.

Backoff schedule (from config):
  offense 1 -> banned 10 min  -> unbanned after 10 min
  offense 2 -> banned 30 min  -> unbanned after 30 min
  offense 3 -> banned 2 hours -> unbanned after 2 hours
  offense 4+ -> permanent (until=-1, never unbanned automatically)
"""
import time
import logging
import subprocess
import threading

from notifier import Notifier

log = logging.getLogger("unbanner")


class UnbanScheduler:
    def __init__(self, cfg, state):
        self.state = state
        self.cfg = cfg
        self.notifier = Notifier(cfg)
        self.audit_log = cfg.get("audit_log", "/app/audit.log")
        self._lock = threading.Lock()

    def _check_and_unban(self) -> None:
        now = time.time()
        to_unban = []

        with self._lock:
            for ip, info in list(self.state["banned"].items()):
                until = info.get("until", -1)
                if until == -1:
                    continue          # permanent ban, skip
                if now >= until:
                    to_unban.append((ip, info))

        for ip, info in to_unban:
            # Remove iptables rule
            try:
                subprocess.run(
                    ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                    capture_output=True, timeout=5
                )
            except Exception as e:
                log.error(f"iptables unban failed for {ip}: {e}")

            # Remove from state
            with self._lock:
                self.state["banned"].pop(ip, None)

            # Slack notification
            self.notifier.unban_alert(ip, info)

            # Audit log
            ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            dur_str = f"{info.get('duration', '?')}s"
            entry = (
                f"[{ts}] UNBAN ip={ip} | "
                f"condition={info.get('condition', 'N/A')} | "
                f"rate=N/A | baseline=N/A | "
                f"duration={dur_str} | offense={info.get('offense_count', '?')}\n"
            )
            log.info(entry.strip())
            with open(self.audit_log, "a") as f:
                f.write(entry)

    def run(self) -> None:
        """Poll every 10 seconds for expired bans."""
        log.info("Unban scheduler running (10s poll interval)")
        while True:
            time.sleep(10)
            try:
                self._check_and_unban()
            except Exception as e:
                log.error(f"Unbanner error: {e}")
