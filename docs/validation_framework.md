# Network Validation Framework Documentation

## Overview

The Network Validation Framework provides comprehensive testing and validation capabilities for VPC networking components, including:
- Security rule enforcement
- NAT behavior
- Network connectivity
- VPC isolation

## API Reference

### NetworkValidator Class

Main class providing network validation functionality.

#### Security Rule Validation

```python
def validate_security_rules(namespace: str, rules: List[Dict]) -> Tuple[bool, Dict[str, Dict]]
```

Validates security rule enforcement in a network namespace.

**Parameters:**
- `namespace` (str): The namespace to validate rules in
- `rules` (List[Dict]): List of security rules to validate, where each rule has:
  - `direction`: "inbound" or "outbound"
  - `protocol`: "tcp", "udp", or "icmp"
  - `port`: port number (for TCP/UDP)
  - `source`: source CIDR (for inbound) or target CIDR (for outbound)
  - `action`: "allow" or "deny"

**Returns:**
- `Tuple[bool, Dict[str, Dict]]`: Success status and detailed results

#### NAT Behavior Validation

```python
def validate_nat_behavior(namespace: str) -> Tuple[bool, Dict[str, Dict]]
```

Validates NAT functionality including outbound access, DNS resolution, and source NAT.

**Parameters:**
- `namespace` (str): The namespace to validate NAT behavior in

**Returns:**
- `Tuple[bool, Dict[str, Dict]]`: Success status and detailed results

## Usage Examples

### 1. Security Rule Validation

```python
validator = NetworkValidator()

# Define security rules
rules = [
    {
        "direction": "inbound",
        "protocol": "tcp",
        "port": 80,
        "source": "0.0.0.0/0",
        "action": "allow"
    },
    {
        "direction": "outbound",
        "protocol": "tcp",
        "port": 443,
        "source": "0.0.0.0/0",
        "action": "allow"
    }
]

# Validate rules
success, results = validator.validate_security_rules("vpc1-public", rules)
```

### 2. NAT Behavior Testing

```python
validator = NetworkValidator()

# Test NAT behavior in public namespace
success, results = validator.validate_nat_behavior("vpc1-public")

# Check specific test results
if results["outbound_internet"]["success"]:
    print("Outbound internet access working")
if results["dns_resolution"]["success"]:
    print("DNS resolution working")
```

### 3. VPC Isolation Testing

```python
validator = NetworkValidator()

# Test isolation between two VPCs
success, error = validator.validate_vpc_isolation("vpc1", "vpc2")
```

## Test Cases

### Security Rules

1. Default Deny Behavior
   - Test access to common ports (22, 80, 443, 8080)
   - Verify UDP ports (53, 123) are blocked
   - Expected: All connections should fail without explicit allow rules

2. Inbound Rule Testing
   - Test allowed ports with correct source CIDR
   - Test denied ports
   - Test allowed ports with incorrect source CIDR
   - Expected: Only allowed combinations should succeed

3. Outbound Rule Testing
   - Test allowed destinations and ports
   - Test blocked destinations
   - Test protocol-specific rules (TCP/UDP/ICMP)
   - Expected: Traffic should match rule specifications

### NAT Behavior

1. Outbound Internet Access
   - Test HTTP/HTTPS connectivity
   - Test ICMP (ping) to internet hosts
   - Expected: Successful outbound connections

2. DNS Resolution
   - Test DNS server accessibility
   - Test actual domain resolution
   - Expected: Successful name resolution

3. Source NAT
   - Verify internal IP is masked
   - Check external IP visibility
   - Expected: Internal IP should not be visible externally

### VPC Isolation

1. Basic Isolation
   - Test direct connectivity between VPC namespaces
   - Expected: No direct connectivity

2. Cross-VPC Communication
   - Test with and without peering
   - Expected: Communication only when peering is configured

## Best Practices

1. Rule Testing
   - Always test both positive and negative cases
   - Include edge cases in CIDR ranges
   - Test all supported protocols

2. Performance
   - Use short timeouts for connection tests
   - Implement parallel testing where possible
   - Clean up temporary resources

3. Troubleshooting
   - Enable detailed logging for failed tests
   - Verify network setup before rule testing
   - Check system requirements (IP forwarding, iptables)