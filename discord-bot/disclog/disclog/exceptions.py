"""
Disclog exceptions
"""


class DisclogError(Exception):
    """Base exception for disclog errors."""
    pass


class DisclogAuthError(DisclogError):
    """Raised when authentication fails (IP not whitelisted)."""
    pass


class DisclogRateLimitError(DisclogError):
    """Raised when rate limit is exceeded."""
    pass


class DisclogConnectionError(DisclogError):
    """Raised when connection to server fails."""
    pass


class DisclogTimeoutError(DisclogError):
    """Raised when request times out."""
    pass
