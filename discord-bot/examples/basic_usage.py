#!/usr/bin/env python3
"""
Basic usage example for disclog

This script demonstrates how to use the disclog library to send logs
to the AWD Logger Discord Bot.
"""

import os
import random
import time

from disclog import *


def main():
    # Configure the client
    # You can also use environment variables:
    # export DISCLOG_HOST=192.168.1.100
    # export DISCLOG_PORT=8080
    
    configure(
        host=os.getenv("DISCLOG_HOST", "localhost"),
        port=int(os.getenv("DISCLOG_PORT", "8080")),
        default_channel="demo",
    )
    
    print("Sending logs to AWD Logger...")
    
    # Basic logging
    log("Hello from disclog! This is a basic log message.")
    
    # Different log levels
    debug("This is a debug message - useful for development")
    info("This is an info message - general information")
    warn("This is a warning - something might be wrong")
    error("This is an error - something went wrong!")
    success("This is a success message - something worked!")
    
    # Attack detection
    attack(
        "SQL Injection attempt detected!",
        target="192.168.1.10",
        payload="' OR 1=1--",
        user_agent="sqlmap/1.0",
        severity="high",
    )
    
    # Flag tracking
    flag(
        "Flag captured successfully!",
        flag_value="CTF{example_flag_12345}",
        service="web",
        target="192.168.1.5",
        points=100,
    )
    
    # Advanced logging with custom fields
    log(
        "Service health check completed",
        level="info",
        title="Health Check",
        service="api-server",
        team="team1",
        tags=["health", "monitoring"],
        fields={
            "cpu_percent": 45.2,
            "memory_mb": 1024,
            "uptime_seconds": 3600,
        },
    )
    
    # Simulate some AWD competition events
    services = ["web", "pwn", "crypto", "misc"]
    teams = ["team1", "team2", "team3", "team4"]
    
    for i in range(5):
        service = random.choice(services)
        team = random.choice(teams)
        
        if random.random() > 0.7:
            # Simulate an attack detection
            attack(
                f"Suspicious activity on {service}",
                channel="attacks",
                service=service,
                team=team,
                severity=random.choice(["low", "medium", "high"]),
            )
        else:
            # Simulate normal service activity
            success(
                f"Service {service} is healthy",
                channel="services",
                service=service,
                team=team,
            )
        
        time.sleep(0.5)
    
    print("All logs sent successfully!")


if __name__ == "__main__":
    main()
