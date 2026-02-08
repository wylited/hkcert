# 🏆 Team Icebird - HKCERT CTF 2026

> **🥈 Secured 2nd Place out of 99+ Tertiary Teams!**
>
> **⚠️ ARCHIVED**: This repository is now archived as the HKCERT 2026 Finals have concluded.

# HKCERT CTF AWD Repository

This repository contains the challenges, exploits, and infrastructure tooling for the HKCERT Capture The Flag (CTF) Attack-Defense (AWD) competition. It includes a comprehensive framework for developing exploits, managing attacks, and logging activities to Discord.

## 📂 Repository Structure

### Challenges
*   **`babyenc/`**: Cryptography/Encoding challenge.
*   **`babypython/`**: Python-based challenge (likely Web or Misc).
*   **`coshell/`**: Shell/Pwn challenge.
*   **`eznote/`**: Note-taking application (Web/Pwn).
*   **`ezvm/`**: Virtual Machine challenge.
*   **`lasp/`**: "LaoSparrow" challenge (VM/Compiler).
*   **`minioa/`**: Java/Jar based challenge.
*   **`sayako/`**: Challenge involving certificates/instructions.
*   **`simpleblog/`**: Blog application (Web).
*   **`example-chal/`**: Template directory for creating new challenges.

### Infrastructure & Tools
*   **`discord-bot/`**: Rust-based Discord logging server for AWD events.
*   **`webhooks/`**: Configuration for GitHub webhooks.
*   **`practice/`**: VPN configuration and connection scripts.
*   **`wyli/`**: User directory containing utilities and documentation.

## 🚀 Getting Started

### Prerequisites
*   Python 3.7+
*   `pip` (Python package manager)
*   Rust (for building the Discord bot)
*   `git`

### Installation

1.  **Install Python Dependencies:**
    ```bash
    pip install pwntools requests openpyxl
    ```

2.  **Set up VPN (if required):**
    Navigate to `practice/` and run the connection script:
    ```bash
    cd practice
    sudo ./connect.sh
    ```

## 🛠️ AWD Framework

The repository uses a custom Python framework for managing exploits and flag submissions. The core libraries are `awd_lib.py` and `pwn_lib.py`.

### `awd_lib.py` - Core Library
Handles configuration, target management, flag submission, and logging.

**Key Functions:**
*   `chal(creds_file=...)`: Configures the challenge environment.
*   `targets()`: Returns a list of target IPs (excluding your own).
*   `submit(flag, target=ip)`: Submits a captured flag to the scoring server.
*   `our_ip()`: Returns your team's IP address.
*   `setup_auth()`: Downloads and configures the SSH key (`auth.pem`).
*   `discord.*`: Interface for sending logs to the Discord bot.

### `pwn_lib.py` - Pwn Utilities
Provides helpers for binary exploitation, wrapping `pwntools`.

**Key Functions:**
*   `setup_binary(path, libc)`: Initializes ELF and ROP objects.
*   `shortcuts(io)`: Creates short aliases for IO operations (e.g., `sla` for `sendlineafter`).
*   `leak_addr(io, prefix)`: Helper to receive and unpack leaked addresses.

### Exploit Templates
Each challenge directory typically contains:
*   `pwn.py`: Template for binary exploitation.
*   `web.py`: Template for web exploitation.
*   `recon.sh`: Script for initial reconnaissance.

## 🤖 Discord Logger

The `discord-bot` directory contains a high-performance logging system written in Rust. It allows exploits to send rich logs (attacks, flags, errors) to a Discord server.

### Features
*   **HTTP API**: Simple POST requests to send logs.
*   **Rich Embeds**: Color-coded logs for different severities (Info, Warn, Error, Attack, Flag).
*   **Rate Limiting**: Prevents spamming Discord API.
*   **IP Whitelisting**: Secures the logging endpoint.

### Running the Bot
1.  Navigate to `discord-bot/`.
2.  Copy `.env.example` to `.env` and configure your Discord token.
3.  Build and run:
    ```bash
    cargo run --release
    ```

### Using in Exploits
```python
from awd_lib import discord

# Configure
discord.configure("LOG_SERVER_IP", 4545)

# Log events
discord.info("Exploit started")
discord.attack("SQL Injection", target="10.0.0.5")
discord.flag("Captured!", flag="HKCERT{...}", target="10.0.0.5")
```

## 📝 Usage Guide

### Running an Exploit
Navigate to a challenge directory (e.g., `babyenc`) and run the exploit script.

```bash
# Attack all targets
python3 exploit_babyenc.py

# Attack a specific target
python3 exploit_babyenc.py 172.24.84.11

# Run continuously (loop mode)
python3 exploit_babyenc.py --loop
```

### Developing a New Exploit
1.  Copy `example-chal/` or an existing challenge folder.
2.  Edit `pwn.py` or `web.py`.
3.  Implement the `exploit(ip)` function to return the flag.
4.  Test locally using `python3 exploit.py local`.

## 📚 Documentation
*   **[AWD Library Documentation](wyli/AWD_LIB_README.md)**: Detailed API reference for `awd_lib`.
*   **[Discord Bot Documentation](discord-bot/README.md)**: Setup and API guide for the logger.
*   **[Webhooks](webhooks/readme.md)**: Information about GitHub integration.

## ⚠️ Rules & Etiquette
*   Do not delete or corrupt other teams' services unless specified.
*   Do not attack the infrastructure (scoring server, visualization).
*   Respect the competition scope and rules.

---
*Generated for HKCERT CTF Team*
