# Connection Tools (hkCERT INStance automation)
WIP WIP WIP WIP

**Completely tested on Kali Linux. LMK if it doesn't work on Windows/Some Distros u using**

## Installation
```
pip install -e .
```

## Usage

### TL;DR
```bash
certins s -x path/to/chall.xls # s for ssh, providing xls will trigger init.
certins s chall
certins f chall up local/file/path remote/file/path # f for file
certins f chall down remote/file/path [local/dir/or/file/path]
certins t # t for tags. view all saved instance tags
```

The `certins` CLI tool provides four main commands: `setup`, `ssh`, `files`, and `tags`.

### 1. Setup Configuration
Create a new connection configuration either interactively or from an Excel sheet.

- **Interactive Setup:**
  ```bash
  certins setup --new
  ```
  Follow the prompts to enter the host, username, and path to your PEM key.

- **From XLS File:**
  ```bash
  certins setup -x path/to/connection.xls
  ```

### 2. SSH Connection
Connect to a configured host using its tag.

```bash
certins ssh <tag>
```
If using an XLS file without prior setup, you can also pass it directly (this will also save the config):
```bash
certins ssh -x path/to/connection.xls
```

### 3. File Transfer
Transfer files between your local machine and the remote host via SCP.

- **Upload (Local -> Remote):**
  ```bash
  certins files <tag> up <local_file> <remote_path>
  ```
  Example: `certins files mytag up ./script.sh /home/user/`

- **Download (Remote -> Local):**
  ```bash
  certins files <tag> down <remote_file> <local_path>
  ```
  Example: `certins files mytag down /var/log/syslog ./logs/`
  If `<local_path>` is a directory, the file will be saved with its original name inside that directory.
### 4. List Tags
List all configured tags and their connection details.

```bash
certins tags
```
