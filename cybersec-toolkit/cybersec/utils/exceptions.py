"""Custom exceptions for the Cybersecurity Toolkit."""


class CyberSecException(Exception):
    """Base exception for the Cybersecurity Toolkit."""
    pass


class ConfigurationError(CyberSecException):
    """Raised when there's an issue with configuration."""
    pass


class DependencyError(CyberSecException):
    """Raised when a required dependency is missing."""
    pass


class PermissionError(CyberSecException):
    """Raised when insufficient permissions for an operation."""
    pass


class NetworkError(CyberSecException):
    """Raised when network-related operations fail."""
    pass


class FirewallError(CyberSecException):
    """Raised when firewall operations fail."""
    pass


class DockerError(CyberSecException):
    """Raised when Docker-related operations fail."""
    pass


class ScanError(CyberSecException):
    """Raised when scanning operations fail."""
    pass


class ValidationError(CyberSecException):
    """Raised when validation fails."""
    pass