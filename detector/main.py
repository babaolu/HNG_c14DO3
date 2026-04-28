"""
main.py — Entry point. Wires all threads together and starts the daemon.
"""
import threading
import logging
import time
import yaml

from monitor import LogMonitor
from baseline import BaselineTracker
from detector import AnomalyDetector
from unbanner import UnbanScheduler
from dashboard import run_dashboard

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
log = logging.getLogger("main")


def load_config(path="config.yaml"):
    with open(path) as f:
        return yaml.safe_load(f)


def main():
    cfg = load_config()
    log.info("HNG Anomaly Detection Engine starting...")

    # Shared state — passed by reference into each module
    state = {
        "banned": {},          # ip -> {until, offense_count, condition}
        "global_rps": 0.0,
        "top_ips": {},
        "start_time": time.time(),
        "baseline_mean": cfg["baseline"]["floor_mean"],
        "baseline_stddev": cfg["baseline"]["floor_stddev"],
    }

    baseline = BaselineTracker(cfg)
    detector = AnomalyDetector(cfg, state, baseline)
    monitor = LogMonitor(cfg, detector, state)
    unbanner = UnbanScheduler(cfg, state)

    # Each component runs in its own daemon thread
    threads = [
        threading.Thread(target=monitor.run, daemon=True, name="monitor"),
        threading.Thread(target=baseline.run, daemon=True, name="baseline"),
        threading.Thread(target=unbanner.run, daemon=True, name="unbanner"),
    ]
    for t in threads:
        t.start()
        log.info(f"Thread started: {t.name}")

    # Dashboard runs in main thread (Flask)
    run_dashboard(cfg, state, baseline)


if __name__ == "__main__":
    main()
