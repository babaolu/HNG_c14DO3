"""
notifier.py — Slack webhook notifications for ban, unban, and global anomaly events.

All alerts include: condition, current rate, baseline, timestamp,
and ban duration (where applicable).
"""
import time
import logging
import threading
import requests

log = logging.getLogger("notifier")


class Notifier:
    def __init__(self, cfg):
        self.webhook_url = cfg["slack"]["webhook_url"]
        self._lock = threading.Lock()

    def _send(self, payload: dict) -> None:
        """Fire Slack webhook in a background thread (non-blocking)."""
        def _post():
            try:
                resp = requests.post(
                    self.webhook_url,
                    json=payload,
                    timeout=8
                )
                if resp.status_code != 200:
                    log.error(
                        f"Slack webhook returned {resp.status_code}: {resp.text}"
                    )
            except Exception as e:
                log.error(f"Slack notification failed: {e}")

        threading.Thread(target=_post, daemon=True).start()

    def ban_alert(
        self,
        ip: str,
        condition: str,
        rate: float,
        baseline: float,
        duration: int,
        offense: int,
    ) -> None:
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        dur_str = f"{duration}s" if duration != -1 else "permanent"
        text = (
            f":rotating_light: *IP BANNED* `{ip}`\n"
            f"• *Condition:* {condition}\n"
            f"• *Current rate:* {rate:.2f} req/s\n"
            f"• *Baseline mean:* {baseline:.4f} req/s\n"
            f"• *Ban duration:* {dur_str} (offense #{offense})\n"
            f"• *Timestamp:* {ts}"
        )
        self._send({"text": text})
        log.info(f"Slack ban alert sent for {ip}")

    def unban_alert(self, ip: str, info: dict) -> None:
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        dur_str = (
            f"{info.get('duration', '?')}s"
            if info.get("duration", -1) != -1
            else "permanent"
        )
        text = (
            f":unlock: *IP UNBANNED* `{ip}`\n"
            f"• *Previous condition:* {info.get('condition', 'N/A')}\n"
            f"• *Ban duration served:* {dur_str}\n"
            f"• *Offense count:* {info.get('offense_count', '?')}\n"
            f"• *Timestamp:* {ts}"
        )
        self._send({"text": text})
        log.info(f"Slack unban alert sent for {ip}")

    def global_alert(self, condition: str, rate: float, baseline: float) -> None:
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        text = (
            f":warning: *GLOBAL TRAFFIC ANOMALY*\n"
            f"• *Condition:* {condition}\n"
            f"• *Current global rate:* {rate:.2f} req/s\n"
            f"• *Baseline mean:* {baseline:.4f} req/s\n"
            f"• *Action:* Slack alert only (no global block)\n"
            f"• *Timestamp:* {ts}"
        )
        self._send({"text": text})
        log.info("Slack global anomaly alert sent")
