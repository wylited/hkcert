"""
Module-level logging functions for convenience.

These functions use the default client configured via configure().
If no client is configured, a new one will be created with default settings.
"""
from typing import Optional, Dict, Any, List

from .client import get_client


def log(
    message: str,
    channel: Optional[str] = None,
    level: str = "info",
    **kwargs,
) -> Dict[str, Any]:
    """
    Send a log message using the default client.
    
    Args:
        message: Log message
        channel: Channel name (uses default if not specified)
        level: Log level (debug, info, warn, error, critical, success, attack, flag)
        **kwargs: Additional fields
        
    Returns:
        Server response
        
    Example:
        >>> from disclog import log
        >>> log("Service is running", channel="web-service", level="info", team="team1")
    """
    return get_client().log(message, channel, level, **kwargs)


def debug(message: str, channel: Optional[str] = None, **kwargs) -> Dict[str, Any]:
    """
    Send a debug-level log.
    
    Example:
        >>> debug("Processing request", request_id="12345")
    """
    return get_client().debug(message, channel, **kwargs)


def info(message: str, channel: Optional[str] = None, **kwargs) -> Dict[str, Any]:
    """
    Send an info-level log.
    
    Example:
        >>> info("Service started successfully")
    """
    return get_client().info(message, channel, **kwargs)


def warn(message: str, channel: Optional[str] = None, **kwargs) -> Dict[str, Any]:
    """
    Send a warning-level log.
    
    Example:
        >>> warn("High memory usage", usage_percent=85)
    """
    return get_client().warn(message, channel, **kwargs)


def error(message: str, channel: Optional[str] = None, **kwargs) -> Dict[str, Any]:
    """
    Send an error-level log.
    
    Example:
        >>> error("Database connection failed", retry_count=3)
    """
    return get_client().error(message, channel, **kwargs)


def critical(message: str, channel: Optional[str] = None, **kwargs) -> Dict[str, Any]:
    """
    Send a critical-level log (pings @everyone).
    
    Use this for serious issues requiring immediate attention.
    
    Example:
        >>> critical("Service is DOWN!", service="web-api")
    """
    return get_client().critical(message, channel, **kwargs)


def success(message: str, channel: Optional[str] = None, **kwargs) -> Dict[str, Any]:
    """
    Send a success-level log (green color).
    
    Example:
        >>> success("Flag submitted successfully!", flag="CTF{...}")
        >>> success("Exploit executed", target="192.168.1.10")
    """
    return get_client().success(message, channel, **kwargs)


def attack(
    message: str,
    channel: Optional[str] = "attacks",
    target: Optional[str] = None,
    **kwargs,
) -> Dict[str, Any]:
    """
    Send an attack detection log.
    
    Args:
        message: Attack description
        channel: Channel name (default: "attacks")
        target: Target IP or service
        **kwargs: Additional fields
        
    Example:
        >>> attack("SQL injection attempt detected", target="192.168.1.10", payload="' OR 1=1--")
        >>> attack("Brute force detected", target="ssh", attempts=50)
    """
    if target:
        kwargs["target"] = target
    return get_client().attack(message, channel, **kwargs)


def flag(
    message: str,
    channel: Optional[str] = "flags",
    flag_value: Optional[str] = None,
    **kwargs,
) -> Dict[str, Any]:
    """
    Send a flag-related log (gold color).
    
    Args:
        message: Flag message
        channel: Channel name (default: "flags")
        flag_value: The flag value (optional)
        **kwargs: Additional fields
        
    Example:
        >>> flag("Flag captured!", flag_value="CTF{secret_flag}", service="web", points=100)
        >>> flag("Submitting flag", flag_value="CTF{...}", target="192.168.1.5")
    """
    if flag_value:
        kwargs["flag"] = flag_value
    return get_client().flag(message, channel, **kwargs)


def exception(
    exc: Exception,
    message: Optional[str] = None,
    channel: Optional[str] = None,
    **kwargs,
) -> Dict[str, Any]:
    """
    Log an exception with full traceback.
    
    Args:
        exc: The exception to log
        message: Additional message
        channel: Channel name
        **kwargs: Additional fields
        
    Example:
        >>> try:
        ...     risky_operation()
        ... except Exception as e:
        ...     exception(e, "Operation failed", channel="errors")
    """
    import traceback
    
    tb = traceback.format_exc()
    msg = message or f"Exception: {type(exc).__name__}: {exc}"
    
    kwargs["exception_type"] = type(exc).__name__
    kwargs["exception_message"] = str(exc)
    kwargs["traceback"] = tb
    
    return get_client().error(msg, channel, **kwargs)


def batch(entries: List[Dict[str, Any]], channel: Optional[str] = None) -> Dict[str, Any]:
    """
    Send multiple log entries in one request.
    
    Args:
        entries: List of log entry dictionaries
        channel: Target channel
        
    Returns:
        Server response
        
    Example:
        >>> batch([
        ...     {"message": "Event 1", "level": "info"},
        ...     {"message": "Event 2", "level": "warn"},
        ... ])
    """
    return get_client().batch(entries, channel)


# Decorator for logging function calls
def logged(
    channel: Optional[str] = None,
    level: str = "info",
    log_args: bool = False,
    log_result: bool = False,
):
    """
    Decorator to automatically log function calls.
    
    Args:
        channel: Channel to log to
        level: Log level
        log_args: Whether to log function arguments
        log_result: Whether to log the return value
        
    Example:
        >>> @logged(channel="functions", level="debug")
        ... def my_function(x, y):
        ...     return x + y
    """
    def decorator(func):
        import functools
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            args_str = ""
            if log_args:
                args_list = [repr(a) for a in args]
                kwargs_list = [f"{k}={v!r}" for k, v in kwargs.items()]
                args_str = f" args=[{', '.join(args_list + kwargs_list)}]"
            
            log(f"Calling {func.__name__}{args_str}", channel=channel, level=level)
            
            try:
                result = func(*args, **kwargs)
                if log_result:
                    log(f"{func.__name__} returned: {result!r}", channel=channel, level="debug")
                else:
                    log(f"{func.__name__} completed successfully", channel=channel, level="debug")
                return result
            except Exception as e:
                error(f"{func.__name__} raised {type(e).__name__}: {e}", channel=channel)
                raise
        
        return wrapper
    return decorator
