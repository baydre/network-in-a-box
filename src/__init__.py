"""Network-in-a-Box package initialization."""

from .exceptions import (
    NetworkInABoxError,
    ValidationError,
    ResourceExistsError,
    ResourceNotFoundError,
    NetworkConfigError,
    StateError,
    SecurityRuleError
)

from .validation import (
    validate_vpc_name,
    validate_cidr,
    validate_ip_address,
    validate_port,
    validate_protocol,
    validate_interface_name,
    validate_security_rule,
    check_vpc_conflicts,
    check_cidr_overlap
)

from .state import StateManager
from .monitor import NetworkMonitor

__version__ = '0.1.0'
__all__ = [
    'NetworkInABoxError',
    'ValidationError',
    'ResourceExistsError',
    'ResourceNotFoundError',
    'NetworkConfigError',
    'StateError',
    'SecurityRuleError',
    'validate_vpc_name',
    'validate_cidr',
    'validate_ip_address',
    'validate_port',
    'validate_protocol',
    'validate_interface_name',
    'validate_security_rule',
    'check_vpc_conflicts',
    'check_cidr_overlap',
    'StateManager',
    'NetworkMonitor'
]