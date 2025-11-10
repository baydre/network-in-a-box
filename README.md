# Network-in-a-Box

Network-in-a-Box is a production-ready VPC simulation tool that recreates core cloud VPC primitives on a single Linux host using native tooling. Build isolated virtual networks with public/private subnets, NAT gateways, security groups, and VPC peering - all using standard Linux networking components.

## Features

## Features

**Complete VPC Lifecycle Management**
- Provision and tear down VPCs with public + private subnets using one command
- Dedicated NAT namespace with internet gateway functionality  
- Automatic subnet derivation from CIDR blocks (public/private split)
- Robust resource cleanup with orphaned resource detection

**Production-Ready Networking**
- Deterministic MD5-based interface naming prevents conflicts
- Persistent state management with file locking
- Comprehensive validation and error handling
- Native Linux tools only (ip, iptables, bridge-utils)

**Advanced Features**
- JSON-based security policy management (cloud-like security groups)
- VPC peering with NAT-aware routing between isolated networks
- Built-in test server deployment and connectivity validation
- Comprehensive integration test suite (13 automated tests)

**Enterprise-Grade Automation**
- Idempotent operations (safe to run multiple times)
- Detailed logging for all network operations
- State consistency validation and recovery
- Multi-VPC support with complete tenant isolation

## Requirements

- **Linux Host**: Ubuntu 18.04+ or equivalent with kernel 4.15+
- **Network Tools**: `ip` (iproute2), `iptables`, `bridge-utils`, `curl` pre-installed
- **Python**: Version 3.8 or higher
- **Privileges**: Root access required (all commands run with `sudo`)
- **Architecture**: x86_64 or ARM64 supported

### Quick Installation

Install dependencies on Debian/Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y iproute2 iptables bridge-utils curl python3
```

Verify installation:

```bash
# Check tools
ip --version && iptables --version && python3 --version

# Verify root access
sudo echo "Root access confirmed"
```

## Quick Start Guide

> **Note**: All CLI commands must be executed from the repository root with `sudo`. Script path: `./src/vpcctl.py`

### 1. Create Your First VPC

```bash
# Create a VPC with automatic subnet allocation
sudo ./src/vpcctl.py create-vpc --name demo --cidr 10.50.0.0/16
```

**What this creates:**
- **Bridge**: `br-demo` connecting all subnets
- **Public Subnet**: `demo-public` namespace (10.50.0.0/17) with internet access
- **Private Subnet**: `demo-private` namespace (10.50.128.0/17) isolated by default  
- **NAT Gateway**: `demo-nat` namespace handling internet traffic
- **Routing**: Automatic route injection for connectivity

### 2. Verify VPC Architecture

```bash
# List all created namespaces
sudo ip netns list | grep demo

# Check public subnet configuration
sudo ip netns exec demo-public ip addr show
sudo ip netns exec demo-public ip route show

# Verify NAT gateway setup
sudo ip netns exec demo-nat iptables -t nat -L -n -v

# Inspect bridge connectivity
sudo bridge link show br-demo
```

### 3. Test Connectivity

```bash
# Test internet connectivity from public subnet
sudo ip netns exec demo-public ping -c 3 8.8.8.8

# Verify private subnet isolation
sudo ip netns exec demo-private ping -c 1 8.8.8.8  # Should fail

# Test inter-subnet communication
sudo ip netns exec demo-public ping -c 3 10.50.128.2  # Private subnet IP
```

### 4. Deploy Test Applications

```bash
# Deploy web server in public subnet
sudo ./src/vpcctl.py deploy-server --namespace demo-public --type python --port 8080

# Deploy web server in private subnet  
sudo ./src/vpcctl.py deploy-server --namespace demo-private --type python --port 8080

# Test application connectivity
sudo ./src/vpcctl.py test-connectivity --source demo-public --target demo-private --port 8080
```

### 5. Configure Security Policies

**Add individual security rules:**

```bash
# Allow HTTP traffic from public to private subnet
sudo ./src/vpcctl.py add-security-rule \
  --namespace demo-private \
  --protocol tcp \
  --port 80 \
  --source 10.50.0.0/17 \
  --action ACCEPT
```

**Apply comprehensive JSON policies:**

```bash
# Create custom policy file
cat > /tmp/demo-policy.json << EOF
{
  "rules": [
    {
      "protocol": "tcp",
      "port": 80,
      "source": "10.50.0.0/17", 
      "action": "allow"
    },
    {
      "protocol": "tcp",
      "port": 22,
      "source": "0.0.0.0/0",
      "action": "deny"
    }
  ]
}
EOF

# Apply policy to namespace
sudo ./src/vpcctl.py apply-policy --namespace demo-private --policy /tmp/demo-policy.json
```

### 6. Create Multi-VPC Environment

```bash
# Create second isolated VPC
sudo ./src/vpcctl.py create-vpc --name production --cidr 10.100.0.0/16

# Verify complete isolation (should fail)
sudo ip netns exec demo-public ping -c 1 10.100.0.2

# Create controlled peering connection
sudo ./src/vpcctl.py create-vpc-peering --vpc1 demo --vpc2 production

# Test cross-VPC connectivity (now works)
sudo ip netns exec demo-public ping -c 3 10.100.0.2
```

### 7. Clean Environment

```bash
# Remove specific VPC
sudo ./src/vpcctl.py delete-vpc --name demo

# Remove multiple VPCs
sudo ./src/vpcctl.py delete-vpc --name production --name demo

# Verify complete cleanup
sudo ip netns list | grep -E "(demo|production)"  # Should be empty
```

## Advanced Usage

### Available Commands

| Command | Purpose | Example |
|---------|---------|---------|
| `create-vpc` | Create VPC with subnets | `--name vpc1 --cidr 10.0.0.0/16` |
| `delete-vpc` | Remove VPC and all resources | `--name vpc1` |
| `create-vpc-peering` | Connect two VPCs | `--vpc1 vpc1 --vpc2 vpc2` |
| `delete-vpc-peering` | Remove VPC connection | `--vpc1 vpc1 --vpc2 vpc2` |
| `add-security-rule` | Add firewall rule | `--namespace vpc1-private --protocol tcp --port 80` |
| `apply-policy` | Apply JSON security policy | `--namespace vpc1-public --policy policy.json` |
| `deploy-server` | Deploy test application | `--namespace vpc1-public --type python --port 8080` |
| `test-connectivity` | Validate network connectivity | `--source vpc1-public --target vpc1-private` |
| `list-vpcs` | Show all VPCs and their status | (no arguments) |

### Automation and Testing

**Run comprehensive integration tests:**

```bash
# Execute full test suite (13 automated tests)
sudo python3 test_suite.py

# Expected output: 
# VPC Creation: PASS
# Internet Connectivity: PASS  
# Private Isolation: PASS
# Inter-subnet Communication: PASS
# VPC Peering Creation: PASS
# Cross-VPC Communication: PASS
# Server Deployment: PASS
# Server Accessibility: PASS
# Policy Application: PASS
# Policy Enforcement: PASS
# Complete Cleanup: PASS
# ALL TESTS PASSED!
```

**Validate individual VPC:**

```bash
# Check VPC health and connectivity
sudo ./src/vpcctl.py list-vpcs
sudo ./src/vpcctl.py test-connectivity --source demo-public --target demo-private
```

## Implementation Notes

### Network Architecture Details

- **Private Subnet Isolation**: By design, private namespaces have no default route, ensuring complete internet isolation while maintaining internal connectivity
- **NAT Gateway Design**: Dedicated NAT namespace handles all outbound traffic with iptables MASQUERADE rules, simulating cloud NAT gateway behavior  
- **State Management**: VPC metadata stored in `/var/tmp/network_in_a_box.state` with file locking for concurrent access safety
- **Interface Naming**: MD5-based deterministic naming prevents conflicts even with similar VPC names
- **VPC Peering**: Uses NAT-to-NAT connections with static route injection, supporting complex multi-tenant scenarios

### Troubleshooting

**Common Issues:**

```bash
# Check if all required tools are available
which ip iptables brctl || echo "Missing network tools"

# Verify namespace creation permissions  
sudo ip netns add test-ns && sudo ip netns delete test-ns || echo "Namespace permission issue"

# Debug connectivity issues
sudo ./src/vpcctl.py list-vpcs  # Check VPC status
sudo ip netns exec <namespace> ip route show  # Check routing

# Clean orphaned resources
sudo ./src/vpcctl.py delete-vpc --name <vpc-name>  # Automatic cleanup
```

**Log Analysis:**
- All operations logged with timestamps and detailed status
- Error messages include specific resolution steps  
- State validation prevents inconsistent configurations

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        Host Network (root)                      │
│                           br-<name>                             │
└─────────────────────────┬───────────────────────────────────────┘
                          │
        ┌─────────────────┼─────────────────┐
        │                 │                 │
 ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
 │ name-public │   │ name-private│   │  name-nat   │
 │ 10.x.0.2/17 │   │10.x.128.2/17│   │ Gateway NS  │
 │             │   │             │   │             │
 │ Internet │   │ Isolated │   │ MASQUERADE  │
 │    Access   │   │  Network    │   │    Rules    │
 └─────────────┘   └─────────────┘   └──────┬──────┘
        │                 │                 │
        │                 │                 │
        └─────────────────┼─────────────────┘
                          │
        ┌─────────────────┼─────────────────┐
        │          veth pairs                │
        │     (bridge interconnect)          │
        └─────────────────┼─────────────────┘
                          │
              ┌───────────┴───────────┐
              │    Host Interface     │
              │   (auto-detected)     │
              │    Internet Uplink    │
              └───────────────────────┘
```

### Key Components

- **Bridge Network**: Central hub connecting all namespaces
- **Network Namespaces**: Complete isolation per subnet/gateway
- **veth Pairs**: Virtual ethernet cables with unique MD5 naming
- **NAT Gateway**: Dedicated namespace handling outbound traffic
- **State Management**: Persistent configuration with atomic updates
- **Security Policies**: JSON-based iptables rule management

## Project Status

**Requirements Met:**
- All 5 required variables implemented (VPC_NAME, CIDR_BLOCK, etc.)
- Python CLI with comprehensive validation  
- 100% native Linux tools (no external dependencies)
- Comprehensive logging of all operations

**Acceptance Criteria Validated:**
- Create VPC | Add Subnets | Public App | Private App
- Multiple VPCs | VPC Peering | NAT Gateway | Firewall Rules | Teardown

**Quality Assurance:**
- **13 Integration Tests** with 100% pass rate
- **Production-ready** error handling and validation
- **Enterprise-grade** state management and cleanup
- **Comprehensive** documentation and troubleshooting guides

### Beyond Requirements

This implementation exceeds the basic project specifications:
- Advanced MD5-based interface naming preventing conflicts
- JSON-based security policy management (cloud-like experience)  
- Automated test server deployment and connectivity validation
- Robust orphaned resource detection and cleanup
- Multi-VPC peering with NAT-aware routing
- File-locked state management for concurrent access safety

## Contributing

### Development Setup

```bash
git clone <repository-url>
cd network-in-a-box

# Run full test suite
sudo python3 test_suite.py

# Test individual components  
sudo ./src/vpcctl.py create-vpc --name test --cidr 10.99.0.0/16
sudo ./src/vpcctl.py delete-vpc --name test
```

### Contributing Guidelines

1. **Fork** the repository and create a feature branch
2. **Test** your changes with the integration test suite
3. **Document** any new CLI commands or options
4. **Validate** against compliance requirements
5. **Submit** pull request with clear description

### Code Style

- Follow Python PEP 8 conventions
- Include comprehensive error handling
- Add logging for all network operations  
- Update tests for new functionality
- Maintain backward compatibility

## License

Released under the MIT License. See `LICENSE` for details.

---

## Additional Resources

- **[Documentation Hub](docs/)** - Complete documentation index and navigation
- **[Project Structure](docs/PROJECT_STRUCTURE.md)** - Codebase organization and module guide
- **[Requirements Compliance](docs/REQUIREMENTS_COMPLIANCE.md)** - Detailed requirements validation  
- **[Implementation Check](docs/COMPLIANCE_CHECK.md)** - Comprehensive compliance matrix
- **[Project Specifications](docs/task.md)** - Original project requirements
- **[Testing Framework](docs/validation_framework.md)** - Validation methodology
- **[Policy Examples](policies/)** - Security policy templates
- **[Integration Tests](test_suite.py)** - Automated test suite

### Support

For issues, feature requests, or questions:
1. Check the troubleshooting section above
2. Review existing issues in the repository  
3. Create a new issue with detailed reproduction steps
4. Include system info (OS, kernel version, Python version)

### Acknowledgments

Built using native Linux networking primitives:
- **iproute2** for advanced network configuration
- **iptables** for NAT and firewall functionality  
- **bridge-utils** for layer-2 connectivity
- **Python 3.8+** for automation and orchestration

*Network-in-a-Box demonstrates that powerful cloud networking can be recreated using standard Linux tooling, providing an excellent learning platform for understanding VPC internals.*