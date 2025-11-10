"""Validation utilities for Network-in-a-Box."""

import ipaddress
import re
from typing import Optional, List, Dict
from exceptions import ValidationError

def validate_vpc_name(name: str) -> None:
    """
    Validate VPC name format.
    Must be alphanumeric with hyphens, 1-32 characters.
    """
    if not re.match(r'^[a-zA-Z0-9-]{1,32}$', name):
        raise ValidationError(
            f"Invalid VPC name: {name}. Must be 1-32 characters, "
            "containing only letters, numbers, and hyphens."
        )

def validate_cidr(cidr: str) -> None:
    """Validate CIDR notation and range."""
    try:
        network = ipaddress.ip_network(cidr)
        if network.version != 4:
            raise ValidationError(f"Only IPv4 is supported. Got: {cidr}")
    except ValueError as e:
        raise ValidationError(f"Invalid CIDR notation: {cidr}. Error: {str(e)}")

def validate_ip_address(ip: str) -> None:
    """Validate IP address format."""
    try:
        address = ipaddress.ip_address(ip)
        if address.version != 4:
            raise ValidationError(f"Only IPv4 is supported. Got: {ip}")
    except ValueError as e:
        raise ValidationError(f"Invalid IP address: {ip}. Error: {str(e)}")

def validate_port(port: int) -> None:
    """Validate port number."""
    if not isinstance(port, int) or port < 1 or port > 65535:
        raise ValidationError(
            f"Invalid port number: {port}. Must be between 1 and 65535."
        )

def validate_protocol(protocol: str) -> None:
    """Validate protocol name."""
    valid_protocols = {'tcp', 'udp', 'icmp'}
    if protocol.lower() not in valid_protocols:
        raise ValidationError(
            f"Invalid protocol: {protocol}. Must be one of: {', '.join(valid_protocols)}"
        )

def validate_interface_name(name: str) -> None:
    """Validate network interface name."""
    if not re.match(r'^[a-zA-Z0-9_-]{1,15}$', name):
        raise ValidationError(
            f"Invalid interface name: {name}. Must be 1-15 characters, "
            "containing only letters, numbers, underscores, and hyphens."
        )

def validate_security_rule(rule: Dict) -> None:
    """Validate security rule configuration."""
    required_fields = {'protocol', 'port', 'source', 'action'}
    missing_fields = required_fields - set(rule.keys())
    if missing_fields:
        raise ValidationError(
            f"Missing required fields in security rule: {', '.join(missing_fields)}"
        )

    validate_protocol(rule['protocol'])
    if rule['protocol'].lower() != 'icmp':
        validate_port(rule['port'])
    validate_cidr(rule['source'])
    
    valid_actions = {'ACCEPT', 'DROP'}
    if rule['action'] not in valid_actions:
        raise ValidationError(
            f"Invalid action: {rule['action']}. Must be one of: {', '.join(valid_actions)}"
        )

def check_vpc_conflicts(vpc_name: str, existing_vpcs: List[str]) -> None:
    """Check for VPC naming conflicts."""
    if vpc_name in existing_vpcs:
        raise ValidationError(f"VPC with name '{vpc_name}' already exists.")

def check_cidr_overlap(cidr1: str, cidr2: str) -> bool:
    """Check for CIDR range overlap."""
    try:
        network1 = ipaddress.ip_network(cidr1)
        network2 = ipaddress.ip_network(cidr2)
        return network1.overlaps(network2)
    except ValueError as e:
        raise ValidationError(f"Invalid CIDR format: {str(e)}")