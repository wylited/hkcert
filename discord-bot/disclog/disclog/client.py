"""
Disclog Client - Core HTTP client for AWD Logger
"""
import os
import json
import time
from typing import Optional, Dict, Any, List, Union
from urllib.parse import urljoin
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .exceptions import DisclogError, DisclogAuthError, DisclogRateLimitError


class DisclogClient:
    """
    AWD Logger HTTP client.
    
    This client provides methods to send logs to the AWD Logger Discord Bot.
    
    Usage:
        >>> client = DisclogClient(host="192.168.1.100", port=8080)
        >>> client.log("general", "Hello World")
        >>> client.error("web-service", "Something went wrong", team="team1")
    
    Or use the module-level functions after configuration:
        >>> from disclog import configure, log, error
        >>> configure(host="192.168.1.100", port=8080)
        >>> log("general", "Hello World")
    """

    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        default_channel: Optional[str] = None,
        timeout: float = 10.0,
        default_fields: Optional[Dict[str, Any]] = None,
    ):
        """
        Initialize the Disclog client.
        
        Args:
            host: Server hostname or IP (default: from env DISCLOG_HOST or 'localhost')
            port: Server port (default: from env DISCLOG_PORT or 8080)
            default_channel: Default channel name (default: from env DISCLOG_CHANNEL or 'general')
            timeout: Request timeout in seconds
            default_fields: Default fields to include in all logs
        """
        self.host = host or os.getenv("DISCLOG_HOST", "localhost")
        self.port = port or int(os.getenv("DISCLOG_PORT", "8080"))
        self.default_channel = default_channel or os.getenv("DISCLOG_CHANNEL", "general")
        self.timeout = timeout
        self.default_fields = default_fields or {}
        
        # Setup session with retries
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Headers
        self.session.headers.update({
            "Content-Type": "application/json",
            "User-Agent": f"Disclog/1.0.0 (Python)",
        })

    @property
    def base_url(self) -> str:
        """Get the base URL for the server."""
        return f"http://{self.host}:{self.port}"

    def _make_url(self, channel: str) -> str:
        """Create the full URL for a channel."""
        return f"{self.base_url}/{channel}"

    def _send(
        self,
        channel: str,
        data: Dict[str, Any],
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Send a log entry to the server.
        
        Args:
            channel: Channel name
            data: Log data dictionary
            timeout: Request timeout override
            
        Returns:
            Server response as dictionary
            
        Raises:
            DisclogAuthError: If IP is not whitelisted
            DisclogRateLimitError: If rate limit is exceeded
            DisclogError: For other errors
        """
        url = self._make_url(channel)
        
        try:
            response = self.session.post(
                url,
                json=data,
                timeout=timeout or self.timeout,
            )
            
            # Handle specific status codes
            if response.status_code == 403:
                raise DisclogAuthError(
                    f"IP not whitelisted: {response.json().get('ip', 'unknown')}"
                )
            elif response.status_code == 429:
                raise DisclogRateLimitError(
                    f"Rate limit exceeded. Retry after {response.json().get('retry_after', 60)}s"
                )
            
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.ConnectionError as e:
            raise DisclogError(f"Connection failed: {e}")
        except requests.exceptions.Timeout:
            raise DisclogError("Request timed out")
        except requests.exceptions.HTTPError as e:
            raise DisclogError(f"HTTP error: {e}")
        except json.JSONDecodeError:
            raise DisclogError(f"Invalid JSON response: {response.text}")

    def log(
        self,
        message: str,
        channel: Optional[str] = None,
        level: str = "info",
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Send a log message.
        
        Args:
            message: Log message
            channel: Channel name (default: self.default_channel)
            level: Log level (debug, info, warn, error, critical, success, attack, flag)
            **kwargs: Additional fields (title, team, service, tags, etc.)
            
        Returns:
            Server response
        """
        ch = channel or self.default_channel
        
        data = {
            "message": message,
            "level": level,
            **self.default_fields,
            **kwargs,
        }
        
        return self._send(ch, data)

    def debug(self, message: str, channel: Optional[str] = None, **kwargs) -> Dict[str, Any]:
        """Send a debug log."""
        return self.log(message, channel, "debug", **kwargs)

    def info(self, message: str, channel: Optional[str] = None, **kwargs) -> Dict[str, Any]:
        """Send an info log."""
        return self.log(message, channel, "info", **kwargs)

    def warn(self, message: str, channel: Optional[str] = None, **kwargs) -> Dict[str, Any]:
        """Send a warning log."""
        return self.log(message, channel, "warn", **kwargs)

    def error(self, message: str, channel: Optional[str] = None, **kwargs) -> Dict[str, Any]:
        """Send an error log."""
        return self.log(message, channel, "error", **kwargs)

    def critical(self, message: str, channel: Optional[str] = None, **kwargs) -> Dict[str, Any]:
        """Send a critical log (pings @everyone)."""
        return self.log(message, channel, "critical", ping_everyone=True, **kwargs)

    def success(self, message: str, channel: Optional[str] = None, **kwargs) -> Dict[str, Any]:
        """Send a success log."""
        return self.log(message, channel, "success", **kwargs)

    def attack(self, message: str, channel: Optional[str] = None, **kwargs) -> Dict[str, Any]:
        """Send an attack detection log."""
        return self.log(message, channel, "attack", **kwargs)

    def flag(self, message: str, channel: Optional[str] = None, **kwargs) -> Dict[str, Any]:
        """Send a flag-related log."""
        return self.log(message, channel, "flag", **kwargs)

    def send(
        self,
        message: str,
        channel: Optional[str] = None,
        level: str = "info",
        title: Optional[str] = None,
        team: Optional[str] = None,
        service: Optional[str] = None,
        tags: Optional[List[str]] = None,
        fields: Optional[Dict[str, Any]] = None,
        url: Optional[str] = None,
        thumbnail: Optional[str] = None,
        ping_everyone: bool = False,
        ping_here: bool = False,
        **extra,
    ) -> Dict[str, Any]:
        """
        Send a fully customized log message.
        
        Args:
            message: Main log message
            channel: Target channel
            level: Log level
            title: Embed title
            team: Team identifier
            service: Service identifier
            tags: List of tags
            fields: Additional custom fields
            url: URL to link in embed
            thumbnail: Thumbnail image URL
            ping_everyone: Whether to ping @everyone
            ping_here: Whether to ping @here
            **extra: Any additional fields
            
        Returns:
            Server response
        """
        data = {
            "message": message,
            "level": level,
        }
        
        if title:
            data["title"] = title
        if team:
            data["team"] = team
        if service:
            data["service"] = service
        if tags:
            data["tags"] = tags
        if fields:
            data["fields"] = fields
        if url:
            data["url"] = url
        if thumbnail:
            data["thumbnail"] = thumbnail
        if ping_everyone:
            data["ping_everyone"] = True
        if ping_here:
            data["ping_here"] = True
            
        data.update(extra)
        data.update(self.default_fields)
        
        return self._send(channel or self.default_channel, data)

    def batch(self, entries: List[Dict[str, Any]], channel: Optional[str] = None) -> Dict[str, Any]:
        """
        Send multiple log entries in one request.
        
        Args:
            entries: List of log entry dictionaries
            channel: Target channel
            
        Returns:
            Server response with sent count and errors
        """
        url = f"{self._make_url(channel or self.default_channel)}/batch"
        
        try:
            response = self.session.post(
                url,
                json={"entries": entries},
                timeout=self.timeout,
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            raise DisclogError(f"Batch send failed: {e}")

    def health_check(self) -> bool:
        """
        Check if the server is reachable.
        
        Returns:
            True if server is up, False otherwise
        """
        try:
            response = self.session.get(self.base_url, timeout=5)
            return response.status_code < 500
        except:
            return False

    def __repr__(self) -> str:
        return f"DisclogClient(host={self.host}, port={self.port}, default_channel={self.default_channel})"


# Module-level client instance
_client: Optional[DisclogClient] = None


def configure(
    host: Optional[str] = None,
    port: Optional[int] = None,
    default_channel: Optional[str] = None,
    timeout: Optional[float] = None,
    default_fields: Optional[Dict[str, Any]] = None,
) -> DisclogClient:
    """
    Configure the module-level default client.
    
    This is a convenience function that sets up a global client instance
    that will be used by the module-level logging functions.
    
    Args:
        host: Server hostname or IP
        port: Server port
        default_channel: Default channel for logs
        timeout: Request timeout in seconds
        default_fields: Default fields to include in all logs
        
    Returns:
        The configured client
        
    Example:
        >>> from disclog import configure, log
        >>> configure(host="192.168.1.100", port=8080, default_channel="team1")
        >>> log("Hello World")  # Sends to "team1" channel
    """
    global _client
    _client = DisclogClient(
        host=host,
        port=port,
        default_channel=default_channel,
        timeout=timeout,
        default_fields=default_fields,
    )
    return _client


def get_client() -> DisclogClient:
    """Get the current client instance, creating a default one if needed."""
    global _client
    if _client is None:
        _client = DisclogClient()
    return _client
