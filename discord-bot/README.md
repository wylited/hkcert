# 🔥 AWD Logger

A comprehensive logging system for **Attack With Defense (AWD)** competitions with Discord integration.

## Features

- 🌐 **HTTP API** - Send logs via simple HTTP POST requests
- 🤖 **Discord Bot** - Rich embeds with color-coded severity levels
- 🔒 **IP Whitelist** - Only whitelisted IPs can send logs
- 🚫 **Blacklist Channel** - Track unauthorized access attempts
- 📊 **Statistics** - Track log volumes and patterns
- ⚡ **Rate Limiting** - Prevent spam and abuse
- 🐍 **Python Client** - Easy-to-use Python library (`disclog`)
- 🔧 **Slash Commands** - Manage whitelist via Discord
- 🏷️ **Rich Formatting** - Teams, services, tags, and custom fields
- 📦 **Batch Logging** - Send multiple logs at once

## Architecture

```
┌─────────────────┐     HTTP POST      ┌──────────────────┐
│  Python Script  │ ─────────────────> │   Rust Server    │
│  / Curl / etc   │   /:channel-name   │   (Axum + Bot)   │
└─────────────────┘                    └────────┬─────────┘
                                                │
                                                │ Discord API
                                                │
                                                ▼
                                        ┌──────────────────┐
                                        │  Discord Server  │
                                        │  ┌────────────┐  │
                                        │  │ 🔥 AWD Logs│  │
                                        │  │ • general  │  │
                                        │  │ • attacks  │  │
                                        │  │ • flags    │  │
                                        │  └────────────┘  │
                                        └──────────────────┘
```

## Quick Start

### 1. Setup Discord Bot

1. Go to [Discord Developer Portal](https://discord.com/developers/applications)
2. Create a new application
3. Go to "Bot" section and create a bot
4. Enable these **Privileged Gateway Intents**:
   - Server Members Intent
   - Message Content Intent
5. Copy the bot token
6. Go to "OAuth2" > "URL Generator"
7. Select scopes: `bot`, `applications.commands`
8. Select permissions:
   - Manage Channels
   - View Channels
   - Send Messages
   - Embed Links
   - Attach Files
   - Read Message History
   - Mention Everyone
9. Use the generated URL to invite the bot to your server

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env with your Discord credentials
```

### 3. Run the Server

```bash
# Build the server
cargo build --release

# Run it
cargo run --release
```

### 4. Configure Whitelist

Use the Discord slash command:
```
/whitelist add ip_address:192.168.1.100 description:Team 1 Server
```

### 5. Start Logging

**Using Python:**
```python
from disclog import *

configure(host="192.168.1.100", port=8080)
log("Service is starting up")
success("Flag captured!", flag="CTF{...}")
attack("SQL injection detected", target="192.168.1.5")
```

**Using cURL:**
```bash
curl -X POST http://192.168.1.100:8080/general \
  -H "Content-Type: application/json" \
  -d '{"message": "Hello from cURL", "level": "info"}'
```

## Installation

### Requirements

- Rust 1.70+ (for the server)
- Python 3.7+ (for the Python client, optional)
- Discord server with bot permissions

### Building from Source

```bash
# Clone repository
git clone <repo-url>
cd awd-logger

# Build release binary
cargo build --release

# The binary will be at target/release/awd-logger
```

### Python Client Installation

```bash
cd disclog
pip install -e .
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DISCORD_TOKEN` | Discord bot token | Required |
| `DISCORD_APPLICATION_ID` | Discord application ID | Required |
| `HTTP_HOST` | HTTP server bind address | 0.0.0.0 |
| `HTTP_PORT` | HTTP server port | 8080 |
| `GUILD_ID` | Discord server ID | Optional |
| `LOG_CATEGORY_NAME` | Category for log channels | 🔥 AWD Logs |
| `BLACKLIST_CHANNEL_NAME` | Blacklist channel name | 🚫 blacklist |
| `ADMIN_USER_IDS` | Admin Discord user IDs | Empty |
| `RATE_LIMIT_PER_MINUTE` | Max requests per minute | 60 |
| `MAX_MESSAGE_LENGTH` | Max log message length | 4000 |
| `DATABASE_URL` | SQLite database path | sqlite://awd_logger.db |

### Discord Bot Permissions Required

- `Manage Channels` - Create log channels
- `View Channels` - Read channels
- `Send Messages` - Post logs
- `Send Messages in Threads` - Optional
- `Embed Links` - Rich embeds
- `Attach Files` - File attachments
- `Read Message History` - View history
- `Mention @everyone` - Critical alerts
- `Use Slash Commands` - Register commands

## Usage

### Slash Commands

| Command | Description | Permission |
|---------|-------------|------------|
| `/ping` | Check bot latency | Anyone |
| `/stats` | Show logging statistics | Anyone |
| `/whitelist add` | Add IP to whitelist | Admin |
| `/whitelist remove` | Remove IP from whitelist | Admin |
| `/whitelist list` | List all whitelisted IPs | Admin |
| `/channel list` | List logging channels | Admin |
| `/channel create` | Create new log channel | Admin |
| `/channel delete` | Delete a log channel | Admin |
| `/help` | Show help | Anyone |

### HTTP API Endpoints

#### POST `/:channel_name`

Send a log message to a channel.

**Request:**
```http
POST /general HTTP/1.1
Content-Type: application/json

{
  "message": "Service is running",
  "level": "info",
  "title": "Service Status",
  "team": "team1",
  "service": "web",
  "tags": ["startup", "healthy"],
  "fields": {
    "uptime": "5 minutes",
    "pid": 12345
  },
  "ping_here": false,
  "ping_everyone": false
}
```

**Response:**
```json
{
  "success": true,
  "channel": "general",
  "level": "INFO"
}
```

**Levels:** `debug`, `info`, `warn`, `error`, `critical`, `success`, `attack`, `flag`

#### POST `/:channel_name/batch`

Send multiple logs at once.

**Request:**
```http
POST /general/batch HTTP/1.1
Content-Type: application/json

{
  "entries": [
    {"message": "Event 1", "level": "info"},
    {"message": "Event 2", "level": "warn"},
    {"message": "Event 3", "level": "error"}
  ]
}
```

### Python Client Usage

#### Basic Logging

```python
from disclog import *

# Configure once
configure(host="192.168.1.100", port=8080, default_channel="team1")

# Simple logs
log("Hello World")
debug("Debug info")
info("Information")
warn("Warning!")
error("Error occurred")
critical("Critical alert!")  # Pings @everyone
success("Success!")
```

#### Attack Detection

```python
from disclog import attack

attack(
    "SQL Injection detected",
    target="192.168.1.10",
    payload="' OR 1=1--",
    user_agent="sqlmap/1.0",
    severity="high"
)
```

#### Flag Tracking

```python
from disclog import flag

flag(
    "Flag captured!",
    flag_value="CTF{secret_flag_here}",
    service="web",
    target="192.168.1.5",
    points=100
)
```

#### Advanced Usage

```python
from disclog import log

log(
    "Custom log",
    channel="custom-channel",
    level="info",
    title="My Title",
    team="team1",
    service="api",
    tags=["important", "production"],
    fields={
        "custom_field": "value",
        "count": 42
    },
    url="https://example.com/details",
    ping_here=True
)
```

#### Exception Logging

```python
from disclog import exception

try:
    risky_operation()
except Exception as e:
    exception(e, "Operation failed")
```

#### Function Decorator

```python
from disclog import logged

@logged(channel="functions", level="debug", log_args=True)
def process_data(x, y):
    return x + y
```

## Log Levels

| Level | Color | Emoji | Description |
|-------|-------|-------|-------------|
| `debug` | Gray | 🔍 | Debug information |
| `info` | Blue | ℹ️ | General info |
| `warn` | Orange | ⚠️ | Warnings |
| `error` | Red | ❌ | Errors |
| `critical` | Purple | 🚨 | Critical (pings @everyone) |
| `success` | Green | ✅ | Success |
| `attack` | Bright Red | ⚔️ | Attack detection |
| `flag` | Gold | 🏁 | Flag events |

## Security

### IP Whitelist

Only whitelisted IP addresses can send logs. Non-whitelisted IPs:
1. Receive HTTP 403 Forbidden
2. Have their attempt logged to the blacklist channel
3. Are recorded in the database

### Rate Limiting

- 60 requests per minute per IP (configurable)
- Rate limit resets every minute
- HTTP 429 returned when exceeded

### Discord Permissions

- Slash commands require admin role or `ADMIN_USER_IDS`
- Bot commands check user permissions

## Project Structure

```
awd-logger/
├── Cargo.toml              # Rust dependencies
├── .env.example            # Environment template
├── README.md               # This file
├── migrations/             # Database migrations
│   └── 001_initial.sql
├── src/
│   ├── main.rs            # Entry point
│   ├── config.rs          # Configuration
│   ├── models/
│   │   ├── mod.rs
│   │   ├── log_entry.rs   # Log models
│   │   └── whitelist.rs   # Whitelist models
│   ├── db/
│   │   └── mod.rs         # Database operations
│   ├── api/
│   │   ├── mod.rs         # HTTP API (Axum)
│   │   └── extractors.rs
│   ├── bot/
│   │   ├── mod.rs         # Discord bot
│   │   ├── commands.rs    # Slash commands
│   │   └── handlers.rs    # Event handlers
│   └── utils/
│       ├── mod.rs
│       ├── discord.rs     # Discord utilities
│       └── format.rs      # Formatting utilities
└── disclog/               # Python client library
    ├── setup.py
    ├── README.md
    └── disclog/
        ├── __init__.py
        ├── client.py
        ├── logger.py
        └── exceptions.py
```

## Troubleshooting

### Bot doesn't respond to slash commands

1. Make sure you've invited the bot with `applications.commands` scope
2. Check if `GUILD_ID` is set correctly
3. Wait up to 1 hour for global commands to sync (use `GUILD_ID` for instant sync)
4. Restart the bot

### "IP not whitelisted" errors

1. Use `/whitelist list` to check whitelisted IPs
2. Add your IP with `/whitelist add ip_address:YOUR_IP`
3. Check that your server can reach the bot server

### "Connection refused" errors

1. Check that the server is running (`cargo run`)
2. Verify `HTTP_HOST` and `HTTP_PORT` configuration
3. Check firewall rules
4. Use `0.0.0.0` as `HTTP_HOST` to accept all interfaces

### Database errors

1. Ensure the `data` directory is writable
2. Check `DATABASE_URL` format
3. Delete `awd_logger.db` to reset (loses whitelist data)

## License

MIT License - See LICENSE file for details

## Contributing

Contributions welcome! Please open an issue or pull request.

## Credits

Built with:
- [Axum](https://github.com/tokio-rs/axum) - Web framework
- [Serenity](https://github.com/serenity-rs/serenity) - Discord library
- [Poise](https://github.com/serenity-rs/poise) - Discord framework
- [SQLx](https://github.com/launchbadge/sqlx) - Database

---

Made with ❤️ for CTF and AWD competitions
