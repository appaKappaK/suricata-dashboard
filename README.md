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
git clone https://github.com/appaKappaK/suricata-dashboard.git
cd suricata-dashboard
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
python suricata_dashboard.py
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

By default, `suricata_dashboard.py` is set up to run directly with Python:

```bash
python suricata_dashboard.py
```

To use **Gunicorn**, you need to comment the uncommented and uncomment the commented... 
### Either way the bottom needs to have this uncommented and the other recommented or removed for it to work... SOME ASSEMBLY REQUIRED 
```bash
def create_app():
    # Validate configuration first
    validate_config()
    
    # Start background log monitoring
    monitor_thread = threading.Thread(target=log_monitor, daemon=True)
    monitor_thread.start()
    
    app_logger.info("🚀 Suricata IDS Dashboard v2.0 Starting...")
    app_logger.info(f"📁 Log file: {LOG_FILE}")
    app_logger.info(f"📊 Max lines to read: {MAX_LINES_TO_READ}")
    app_logger.info(f"⏱️ Refresh interval: {REFRESH_INTERVAL}s")
    app_logger.info(f"🔔 High priority threshold: {HIGH_PRIORITY_THRESHOLD} alerts")
    app_logger.info(f"🌐 Dashboard URL: http://{HOST}:{PORT}")
    app_logger.info(f"📝 App logs: logs/suricata_dashboard.log (50MB rotation)")
    
    # Initial log parse
    parse_suricata_log()
    
    return app


# For gunicorn to see:
app = create_app()

if __name__ == '__main__':
    app.run(host=HOST, port=PORT, debug=False)
```

Then you can run Gunicorn like this:

```bash
gunicorn -w 4 -b 0.0.0.0:8080 suricata_dashboard:app
```

- `-w 4` starts 4 worker processes (adjust as needed).
- `-b 0.0.0.0:8080` binds the app to all interfaces on port 8080.
- `suricata_dashboard:app` points Gunicorn to the Flask `app` object returned by `create_app()`.

## License

This project uses the GPL-3.0 license. See `LICENSE` for details.

