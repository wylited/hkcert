"""
Disclog - AWD Competition Logging Client

A comprehensive Python client library for the AWD Logger Discord Bot.
Provides simple logging functions with rich formatting for Attack With Defense competitions.

Quick Start:
    >>> from disclog import *
    >>> log("general", "Service is starting up")
    >>> error("web-service", "Connection failed", team="team1", retry_count=3)
    >>> success("flags", "Flag submitted!", flag="CTF{...}")

Configuration:
    Set environment variables or use configure():
    - DISCLOG_HOST: Server IP/hostname (default: localhost)
    - DISCLOG_PORT: Server port (default: 8080)
    - DISCLOG_CHANNEL: Default channel name (default: general)

Example .env file:
    DISCLOG_HOST=192.168.1.100
    DISCLOG_PORT=8080
    DISCLOG_CHANNEL=team-logs
"""

from .client import DisclogClient, configure, get_client
from .logger import log, debug, info, warn, error, critical, success, attack, flag
from .exceptions import DisclogError, DisclogAuthError, DisclogRateLimitError

__version__ = "1.0.0"
__all__ = [
    # Client
    "DisclogClient",
    "configure",
    "get_client",
    # Logging functions
    "log",
    "debug",
    "info",
    "warn",
    "error",
    "critical",
    "success",
    "attack",
    "flag",
    # Exceptions
    "DisclogError",
    "DisclogAuthError",
    "DisclogRateLimitError",
    # Legacy exports for convenience
    "configure",
]

# Default client instance
_default_client: DisclogClient = None


def _get_default_client() -> DisclogClient:
    """Get or create the default client instance."""
    global _default_client
    if _default_client is None:
        _default_client = DisclogClient()
    return _default_client


# Override get_client to use default
def get_client() -> DisclogClient:
    """Get the default client instance."""
    return _get_default_client()


# Re-export configure with default client update
def configure(
    host: str = None,
    port: int = None,
    default_channel: str = None,
    timeout: float = None,
    default_fields: dict = None,
) -> DisclogClient:
    """
    Configure the default disclog client.
    
    Args:
        host: Server hostname or IP
        port: Server port
        default_channel: Default channel for logs
        timeout: Request timeout in seconds
        default_fields: Default fields to include in all logs
        
    Returns:
        The configured client instance
    """
    global _default_client
    _default_client = DisclogClient(
        host=host,
        port=port,
        default_channel=default_channel,
        timeout=timeout,
        default_fields=default_fields,
    )
    return _default_client
