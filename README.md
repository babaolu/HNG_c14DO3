# HNG Cloud.ng — Anomaly Detection Engine

A real-time HTTP traffic anomaly detector running alongside Nextcloud,
powered by Nginx JSON logs, sliding-window rate tracking, and automatic
iptables banning.

---

## Live URLs

- **Server IP:** `YOUR_SERVER_IP`
- **Metrics Dashboard:** `http://metrics.yourdomain.com` (port 8080)

---

## Language Choice

**Python 3.11** — chosen for its expressive `collections.deque`, native
threading primitives, and Flask for the dashboard. The logic is readable
and easy to audit, which matters for a security tool.

---

## How the Sliding Window Works

Each sliding window is a `collections.deque` of unix timestamps.

```
global_window: deque([1700000001.2, 1700000001.8, 1700000002.1, ...])
ip_windows:    {"1.2.3.4": deque([...]), "5.6.7.8": deque([...])}
```

On every log line:
1. Append the current timestamp to the right of the deque.
2. Evict from the left: `while dq[0] < now - 60: dq.popleft()`
3. Rate = `len(dq) / 60`

This is O(1) amortised — no scanning the full window every tick.

---

## How the Baseline Works

- **Window:** 1800 seconds (30 minutes) of per-second request counts.
- **Storage:** A rolling `deque` of `(timestamp, count)` tuples plus 24
  per-hour slot deques (indexed by `unix_hour % 24`).
- **Recalculation:** Every 60 seconds we compute population mean and stddev.
- **Preference:** If the current hour slot has ≥ 120 data points (2 min),
  we use it. Otherwise we fall back to the full 30-min rolling window.
- **Floors:** `effective_mean = max(computed_mean, 0.1)` and
  `effective_stddev = max(computed_stddev, 0.05)` — prevents division by
  zero in the z-score formula during low-traffic periods.

---

## Detection Logic

For each log line, `detector.py` computes:

```
z_score = (current_rate - effective_mean) / effective_stddev
```

An anomaly fires when **either** condition is true:
- `z_score >= 3.0` (3 standard deviations above normal), **or**
- `current_rate >= 5.0 × effective_mean`

**Error surge:** if an IP's 4xx/5xx rate is ≥ 3× the baseline error rate,
thresholds tighten to `zscore >= 1.5` and `rate >= 2.5x mean`.

**Per-IP:** iptables DROP + Slack alert within 10 seconds.  
**Global:** Slack alert only (no blanket block).

---

## How iptables Blocks an IP

```bash
# Ban
iptables -I INPUT -s <ip> -j DROP

# Unban
iptables -D INPUT -s <ip> -j DROP
```

`-I` inserts at position 1 (highest priority). The detector container
runs with `cap_add: NET_ADMIN` and `network_mode: host` to reach the
host's netfilter tables.

Backoff schedule (config-driven):
| Offense | Duration  |
|---------|-----------|
| 1st     | 10 min    |
| 2nd     | 30 min    |
| 3rd     | 2 hours   |
| 4th+    | Permanent |

---

## Setup — Fresh VPS to Fully Running

```bash
# 1. Install Docker
curl -fsSL https://get.docker.com | sh
apt install -y docker-compose-plugin

# 2. Clone repo
git clone https://github.com/YOUR_ORG/hng-detector.git
cd hng-detector

# 3. Set Slack webhook
nano detector/config.yaml   # replace webhook_url value

# 4. Create empty audit log (required for bind-mount)
touch detector/audit.log

# 5. Start the stack
docker compose up -d --build

# 6. Watch daemon logs
docker compose logs -f detector

# 7. Verify iptables access
docker compose exec detector iptables -L -n

# 8. Check dashboard JSON
curl http://localhost:8080/api/metrics
```

---

## Blog Post

[Link to your published blog post here]

---

## GitHub Repository

[https://github.com/babaolu/HNG_c14DO3](https://github.com/babaolu/HNG_c14DO3#)
