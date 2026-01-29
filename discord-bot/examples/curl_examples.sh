#!/bin/bash
# Example curl commands for AWD Logger

HOST="${DISCLOG_HOST:-localhost}"
PORT="${DISCLOG_PORT:-8080}"
BASE_URL="http://${HOST}:${PORT}"

echo "Sending logs to ${BASE_URL}..."

# Simple text log
curl -X POST "${BASE_URL}/general" \
  -H "Content-Type: text/plain" \
  -d "Simple text log message"

# JSON log - Info level
curl -X POST "${BASE_URL}/general" \
  -H "Content-Type: application/json" \
  -d '{
    "message": "Service started successfully",
    "level": "info",
    "title": "Service Status",
    "service": "web-api"
  }'

# JSON log - Error level
curl -X POST "${BASE_URL}/errors" \
  -H "Content-Type: application/json" \
  -d '{
    "message": "Database connection failed",
    "level": "error",
    "title": "Connection Error",
    "service": "database",
    "team": "team1",
    "fields": {
      "error_code": 500,
      "retry_count": 3
    }
  }'

# Attack detection log
curl -X POST "${BASE_URL}/attacks" \
  -H "Content-Type: application/json" \
  -d '{
    "message": "SQL Injection attempt detected",
    "level": "attack",
    "title": "Attack Detected",
    "service": "web",
    "source_ip": "10.0.0.50",
    "tags": ["sqli", "critical"],
    "fields": {
      "payload": "'\'' OR 1=1--",
      "user_agent": "sqlmap/1.0"
    }
  }'

# Flag capture log
curl -X POST "${BASE_URL}/flags" \
  -H "Content-Type: application/json" \
  -d '{
    "message": "Flag submitted successfully!",
    "level": "flag",
    "title": "Flag Capture",
    "service": "pwn",
    "team": "team1",
    "fields": {
      "flag": "CTF{example_flag_12345}",
      "points": 100,
      "target": "192.168.1.5"
    }
  }'

# Critical alert (pings @everyone)
curl -X POST "${BASE_URL}/alerts" \
  -H "Content-Type: application/json" \
  -d '{
    "message": "CRITICAL: Service is down!",
    "level": "critical",
    "title": "CRITICAL ALERT",
    "service": "web",
    "ping_everyone": true
  }'

# Batch logs
curl -X POST "${BASE_URL}/general/batch" \
  -H "Content-Type: application/json" \
  -d '{
    "entries": [
      {"message": "Event 1", "level": "info"},
      {"message": "Event 2", "level": "warn"},
      {"message": "Event 3", "level": "error"}
    ]
  }'

echo "All logs sent!"
EOF
chmod +x examples/curl_examples.sh
