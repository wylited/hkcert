# Disclog - AWD Logger Python Client

A comprehensive Python client library for the AWD Logger Discord Bot, designed for Attack With Defense competitions.

## Installation

```bash
pip install disclog
```

Or install from source:

```bash
cd disclog
pip install -e .
```

## Quick Start

```python
from disclog import *

# Configure once
configure(host="192.168.1.100", port=8080, default_channel="team1")

# Start logging!
log("Service started successfully")
info("Processing request #12345")
warn("High memory usage: 85%")
error("Database connection failed", retry_count=3)
success("Flag captured!", flag="CTF{...}", points=100)
critical("SERVICE IS DOWN!", ping_everyone=True)
```

## Configuration

### Environment Variables

```bash
export DISCLOG_HOST=192.168.1.100
export DISCLOG_PORT=8080
export DISCLOG_CHANNEL=general
```

### Code Configuration

```python
from disclog import configure

configure(
    host="192.168.1.100",
    port=8080,
    default_channel="team1",
    timeout=30.0,
    default_fields={"team": "team1", "service": "web"}
)
```

## Usage Examples

### Basic Logging

```python
from disclog import log, debug, info, warn, error, success

# Simple logs
log("Hello World")
debug("Debug information")
info("Service is running")
warn("Warning message")
error("Error occurred")
success("Operation completed")
```

### Advanced Logging

```python
from disclog import log

# With custom fields
log(
    "Attack detected!",
    channel="attacks",
    level="attack",
    title="SQL Injection Attempt",
    team="team1",
    service="web",
    source_ip="10.0.0.5",
    tags=["sqli", "critical"],
    fields={
        "payload": "' OR 1=1--",
        "user_agent": "sqlmap/1.0"
    }
)
```

### Attack Detection

```python
from disclog import attack

# Log attack detections
attack(
    "Brute force detected on SSH",
    target="192.168.1.10",
    attempts=50,
    username="root",
    timeframe="5m"
)
```

### Flag Tracking

```python
from disclog import flag

# Log flag submissions
flag(
    "Successfully submitted flag!",
    flag_value="CTF{secret_flag_here}",
    service="web",
    target="192.168.1.5",
    points=100
)
```

### Exception Logging

```python
from disclog import exception

try:
    risky_operation()
except Exception as e:
    exception(e, "Operation failed", channel="errors")
```

### Batch Logging

```python
from disclog import batch

# Send multiple logs at once
batch([
    {"message": "Event 1", "level": "info"},
    {"message": "Event 2", "level": "warn", "tags": ["important"]},
    {"message": "Event 3", "level": "error"},
], channel="events")
```

### Using the Client Directly

```python
from disclog import DisclogClient

client = DisclogClient(
    host="192.168.1.100",
    port=8080,
    default_channel="my-channel"
)

# Send logs
client.info("Hello from client")
client.error("Something went wrong", team="team1")

# Check server health
if client.health_check():
    print("Server is up!")
```

### Decorator for Function Logging

```python
from disclog import logged

@logged(channel="functions", level="debug", log_args=True)
def process_data(data):
    return data.upper()

process_data("hello")  # Automatically logs function call
```

## Log Levels

| Level    | Color   | Emoji | Description                    |
|----------|---------|-------|--------------------------------|
| debug    | Gray    | 🔍    | Debug information              |
| info     | Blue    | ℹ️    | General information            |
| warn     | Orange  | ⚠️    | Warnings                       |
| error    | Red     | ❌    | Errors                         |
| critical | Purple  | 🚨    | Critical (pings @everyone)     |
| success  | Green   | ✅    | Success messages               |
| attack   | Red     | ⚔️    | Attack detection               |
| flag     | Gold    | 🏁    | Flag-related events            |

## Error Handling

```python
from disclog import log, DisclogAuthError, DisclogRateLimitError, DisclogError

try:
    log("Important message")
except DisclogAuthError:
    print("IP not whitelisted!")
except DisclogRateLimitError as e:
    print(f"Rate limited: {e}")
except DisclogError as e:
    print(f"Error: {e}")
```

## License

MIT License
