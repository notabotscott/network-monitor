"""Unit tests for BannerGrabber helper functions (no network calls)."""
from __future__ import annotations

from monitor.scanner import _clean_banner


class TestCleanBanner:
    def test_plain_ascii(self):
        assert _clean_banner(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu\r\n") == "SSH-2.0-OpenSSH_8.9p1 Ubuntu"

    def test_ftp_greeting(self):
        assert _clean_banner(b"220 vsftpd 3.0.5\r\n") == "220 vsftpd 3.0.5"

    def test_smtp_greeting(self):
        raw = b"220 mail.example.com ESMTP Postfix (Ubuntu)\r\n"
        assert "Postfix" in _clean_banner(raw)

    def test_non_printable_replaced(self):
        # Telnet IAC sequences and other binary garbage get replaced with spaces
        result = _clean_banner(b"\xff\xfd\x01Hello\x00Server")
        assert "Hello" in result
        assert "Server" in result

    def test_null_bytes_cleaned(self):
        result = _clean_banner(b"MySQL\x005.7.39\x00")
        assert "MySQL" in result
        assert "\x00" not in result

    def test_empty_bytes_returns_none(self):
        assert _clean_banner(b"") is None

    def test_only_whitespace_returns_none(self):
        assert _clean_banner(b"   \r\n\t  ") is None

    def test_truncated_to_256(self):
        long_banner = b"X" * 1000
        result = _clean_banner(long_banner)
        assert len(result) == 256

    def test_multiline_collapsed(self):
        result = _clean_banner(b"line one\r\nline two\r\n")
        # Multiple whitespace collapsed to single space
        assert "  " not in result

    def test_utf8_decoded(self):
        result = _clean_banner("220 héllo\r\n".encode("utf-8"))
        assert result is not None

    def test_invalid_utf8_replaced_not_crashed(self):
        result = _clean_banner(b"\xff\xfe invalid utf8 \x80\x81 banner")
        assert result is not None
