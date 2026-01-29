"""Tests for disclog client."""
import pytest
from unittest.mock import Mock, patch
from disclog import DisclogClient, configure, log, DisclogError, DisclogAuthError


class TestDisclogClient:
    """Test cases for DisclogClient."""

    def test_init_default(self):
        """Test client initialization with defaults."""
        client = DisclogClient()
        assert client.host == "localhost"
        assert client.port == 8080
        assert client.default_channel == "general"

    def test_init_custom(self):
        """Test client initialization with custom values."""
        client = DisclogClient(
            host="192.168.1.100",
            port=9090,
            default_channel="custom",
        )
        assert client.host == "192.168.1.100"
        assert client.port == 9090
        assert client.default_channel == "custom"

    def test_base_url(self):
        """Test base URL generation."""
        client = DisclogClient(host="example.com", port=3000)
        assert client.base_url == "http://example.com:3000"

    @patch("disclog.client.requests.Session.post")
    def test_log_success(self, mock_post):
        """Test successful log send."""
        mock_response = Mock()
        mock_response.json.return_value = {"success": True}
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response

        client = DisclogClient()
        result = client.log("Test message")

        assert result["success"] is True
        mock_post.assert_called_once()

    @patch("disclog.client.requests.Session.post")
    def test_log_auth_error(self, mock_post):
        """Test authentication error handling."""
        mock_response = Mock()
        mock_response.json.return_value = {"ip": "10.0.0.1"}
        mock_response.status_code = 403
        mock_post.return_value = mock_response

        client = DisclogClient()
        with pytest.raises(DisclogAuthError):
            client.log("Test message")

    def test_different_levels(self):
        """Test different log level methods."""
        client = DisclogClient()
        
        with patch.object(client, "_send") as mock_send:
            mock_send.return_value = {"success": True}
            
            client.debug("Debug message")
            mock_send.assert_called()
            
            client.info("Info message")
            client.warn("Warning")
            client.error("Error")
            client.success("Success")
            client.attack("Attack")
            client.flag("Flag")

    def test_configure(self):
        """Test module-level configure function."""
        client = configure(host="test.com", port=1234)
        assert client.host == "test.com"
        assert client.port == 1234


if __name__ == "__main__":
    pytest.main([__file__])
