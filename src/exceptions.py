"""Custom exceptions for Network-in-a-Box."""

class NetworkInABoxError(Exception):
    """Base exception class for Network-in-a-Box."""
    pass

class ValidationError(NetworkInABoxError):
    """Raised when input validation fails."""
    pass

class ResourceExistsError(NetworkInABoxError):
    """Raised when attempting to create a resource that already exists."""
    pass

class ResourceNotFoundError(NetworkInABoxError):
    """Raised when a requested resource doesn't exist."""
    pass

class NetworkConfigError(NetworkInABoxError):
    """Raised when network configuration fails."""
    pass

class StateError(NetworkInABoxError):
    """Raised when there are state management issues."""
    pass

class SecurityRuleError(NetworkInABoxError):
    """Raised when security rule configuration fails."""
    pass