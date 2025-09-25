# Suricata IDS Dashboard

## Overview

This dashboard provides a sleek, real-time interface for monitoring Suricata IDS alerts. It displays statistics, high/medium/low priority alerts, and allows advanced search and filtering.

## Features

- Real-time updates of Suricata alerts.
- High, medium, and low priority alert visualization.
- Advanced search by signature, IP, port, or category.
- Auto-refresh with adjustable interval.
- Performance metrics including log size, processing time, and alerts per second.

## Requirements

- Python 3.x
- Suricata IDS installed and logging alerts to eve.json
- Web browser for accessing the dashboard

## Setup

1. Clone this repository:

```bash
git clone https://github.com/appaKappaK/Suricata-dashboard.git
cd Suricata-dashboard
```

2. Create a `.env` file with placeholders for configuration:

```bash
SURICATA_LOG_FILE=/path/to/suricata/eve.json
DASHBOARD_MAX_LINES=5000
DASHBOARD_REFRESH_INTERVAL=10
DASHBOARD_HOST=127.0.0.1
DASHBOARD_PORT=8080
HIGH_PRIORITY_THRESHOLD=10
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Run the dashboard:

```bash
python dashboard.py
```

5. Access the dashboard in your browser:

```
http://<DASHBOARD_HOST>:<DASHBOARD_PORT>
```

## Configuration

- `SURICATA_LOG_FILE`: Path to Suricata's eve.json log.
- `DASHBOARD_MAX_LINES`: Maximum number of lines to read from the log for performance.
- `DASHBOARD_REFRESH_INTERVAL`: Refresh interval in seconds.
- `DASHBOARD_HOST`: Host/IP to bind the dashboard.
- `DASHBOARD_PORT`: Port to serve the dashboard.
- `HIGH_PRIORITY_THRESHOLD`: Number of alerts considered high priority.

## Running with Gunicorn

By default, `dashboard.py` is set up to run directly with Python:

```bash
python dashboard.py
```

If you want to serve the dashboard using **Gunicorn**, you need to adjust the commented/uncommented sections at the bottom of `dashboard.py`. Specifically:

- Uncomment the `create_app()` function and the `app = create_app()` line.
- Comment out (or remove) the direct `app.run(...)` section.

Then you can run Gunicorn like this:

```bash
gunicorn -w 4 -b 0.0.0.0:8080 dashboard:app
```

- `-w 4` starts 4 worker processes (adjust as needed).
- `-b 0.0.0.0:8080` binds the app to all interfaces on port 8080.
- `dashboard:app` points Gunicorn to the Flask `app` object returned by `create_app()`.

This allows production-ready serving with proper multi-threading and request handling.

## License

This project uses the GPL-3.0 license. See `LICENSE` for details.

