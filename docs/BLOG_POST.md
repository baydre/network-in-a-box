# Building a Cloud VPC Network Simulator: Network-in-a-Box Tutorial

*Learn how to create your own Virtual Private Cloud (VPC) simulation using Linux networking primitives*

---

## Table of Contents
1. [Project Overview](#project-overview)
2. [Prerequisites](#prerequisites) 
3. [Installation & Setup](#installation--setup)
4. [Architecture Deep Dive](#architecture-deep-dive)
5. [CLI Usage Examples](#cli-usage-examples)
6. [Testing & Validation](#testing--validation)
7. [Advanced Features](#advanced-features)
8. [Troubleshooting](#troubleshooting)
9. [Cleanup & Resource Management](#cleanup--resource-management)
10. [Next Steps](#next-steps)

---

## Project Overview

**Network-in-a-Box** is a sophisticated VPC (Virtual Private Cloud) simulation tool that recreates core cloud networking primitives on a single Linux host. Think of it as your own AWS VPC running locally - complete with public/private subnets, NAT gateways, security groups, and VPC peering.

### What You'll Build

By the end of this tutorial, you'll have:
- ✅ **Complete VPC Lifecycle Management**: Create and destroy isolated virtual networks
- ✅ **Public/Private Subnets**: With proper internet routing and isolation
- ✅ **NAT Gateway**: Allowing private subnet internet access through public subnet
- ✅ **VPC Peering**: Connect multiple VPCs for inter-network communication
- ✅ **Security Groups**: JSON-based firewall rules like AWS security groups
- ✅ **Test Applications**: Deploy and test web servers in your VPCs

### Why This Matters

Understanding VPC internals helps you:
- **Debug cloud networking issues** more effectively
- **Design better cloud architectures** with deep networking knowledge
- **Prepare for cloud certification exams** with hands-on experience
- **Learn Linux networking** through practical, real-world scenarios

---

## Prerequisites

### System Requirements
- **Linux Host**: Ubuntu 18.04+ or equivalent (kernel 4.15+)
- **Architecture**: x86_64 or ARM64
- **Memory**: Minimum 2GB RAM
- **Storage**: 1GB free space
- **Network**: Internet connectivity for testing

### Required Knowledge
- **Basic Linux CLI**: File operations, sudo usage
- **Networking Fundamentals**: IP addresses, subnets, routing concepts
- **Python Basics**: Understanding command-line scripts (helpful but not required)

### Tools Check
Before starting, verify you have these tools:

```bash
# Check essential networking tools
ip --version && echo "✓ iproute2 available"
iptables --version && echo "✓ iptables available" 
python3 --version && echo "✓ Python 3 available"
which brctl && echo "✓ bridge-utils available"
curl --version && echo "✓ curl available"

# Verify root access capability
sudo echo "✓ Root access confirmed"
```

---

## Installation & Setup

### Step 1: Get the Code

```bash
# Clone the repository
git clone https://github.com/yourusername/network-in-a-box.git
cd network-in-a-box

# Verify repository structure
ls -la
```

**Expected Output:**
```
README.md
Makefile           # Quick setup commands
cleanup.sh         # Resource cleanup script
test_suite.py      # Integration tests
src/               # Main source code
├── vpcctl.py      # Primary CLI tool
├── validation.py  # Input validation
├── state.py       # State management
└── ...
docs/              # Documentation
policies/          # Security policy examples
```

### Step 2: Install Dependencies

Using the Makefile (recommended):

```bash
# Install system dependencies
sudo make install

# Setup development environment
sudo make setup

# Verify installation
make validate
```

Manual installation:

```bash
# Update package lists
sudo apt-get update

# Install required packages
sudo apt-get install -y iproute2 iptables bridge-utils curl python3

# Make scripts executable
chmod +x src/vpcctl.py cleanup.sh
```

### Step 3: Verify Installation

```bash
# Run system validation
sudo make validate

# Expected output:
# Checking root access: ✓ OK
# Checking ip command: ✓ OK
# Checking iptables: ✓ OK
# Checking bridge utils: ✓ OK
# Checking curl: ✓ OK
# Checking Python 3: ✓ OK
# All requirements satisfied!
```

---

## Architecture Deep Dive

### High-Level Architecture

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
 │ Internet ←──│   │ Isolated ←──│   │ MASQUERADE  │
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

### Component Breakdown

#### 1. **Network Namespaces** (Isolation Containers)
- **Public Namespace** (`vpc-public`): Has internet access via NAT
- **Private Namespace** (`vpc-private`): Isolated, no direct internet
- **NAT Namespace** (`vpc-nat`): Handles routing and NAT operations

#### 2. **Bridge Network** (Central Hub)
- **Linux Bridge** (`br-vpc-name`): Connects all namespaces
- **Layer 2 switching** between connected interfaces
- **Broadcast domain** for the entire VPC

#### 3. **veth Pairs** (Virtual Cables)
- **Virtual Ethernet** connections between namespaces and bridge
- **Point-to-point** links with unique MD5-based naming
- **Full duplex** communication

#### 4. **NAT Gateway** (Internet Access)
- **Dedicated namespace** handling outbound traffic
- **iptables MASQUERADE** rules for source NAT
- **Route injection** for internet connectivity

### Network Flow Examples

#### Internet Access from Public Subnet:
```
Public Namespace → Bridge → NAT Namespace → Host Interface → Internet
```

#### Private Subnet Isolation:
```
Private Namespace → Bridge → NAT Namespace (internal routes only)
# No default route = no internet access
```

#### Inter-VPC Communication (with Peering):
```
VPC1 Namespace → VPC1 Bridge → Peering veth → VPC2 Bridge → VPC2 Namespace
```

---

## CLI Usage Examples

### Basic VPC Operations

#### Creating Your First VPC

```bash
# Create a VPC with automatic subnet allocation
sudo ./src/vpcctl.py create-vpc --name demo --cidr 10.50.0.0/16
```

**What this creates:**
- **Bridge**: `br-demo` connecting all subnets
- **Public Subnet**: `demo-public` namespace (10.50.0.0/17) with internet access
- **Private Subnet**: `demo-private` namespace (10.50.128.0/17) isolated by default  
- **NAT Gateway**: `demo-nat` namespace handling internet traffic

#### Exploring Your VPC

```bash
# List all created namespaces
sudo ip netns list | grep demo

# Expected output:
# demo-nat (id: 2)
# demo-private (id: 1) 
# demo-public (id: 0)

# Check public subnet configuration
sudo ip netns exec demo-public ip addr show
sudo ip netns exec demo-public ip route show

# Verify bridge connectivity
sudo bridge link show br-demo
```

#### Testing Connectivity

```bash
# Test internet connectivity from public subnet
sudo ip netns exec demo-public ping -c 3 8.8.8.8

# Expected: 0% packet loss (success)

# Verify private subnet isolation  
sudo ip netns exec demo-private ping -c 1 8.8.8.8

# Expected: 100% packet loss or "Network unreachable" (correct isolation)

# Test inter-subnet communication
sudo ip netns exec demo-public ping -c 3 10.50.128.2  # Private subnet IP
```

### Advanced VPC Operations

#### Multi-VPC Environment

```bash
# Create second VPC with different CIDR
sudo ./src/vpcctl.py create-vpc --name production --cidr 10.100.0.0/16

# Verify complete isolation (should fail)
sudo ip netns exec demo-public ping -c 1 10.100.0.2

# Create controlled peering connection
sudo ./src/vpcctl.py create-vpc-peering --vpc1 demo --vpc2 production

# Test cross-VPC connectivity (now works)
sudo ip netns exec demo-public ping -c 3 10.100.0.2
```

#### Application Deployment

```bash
# Deploy web server in public subnet
sudo ./src/vpcctl.py deploy-server --namespace demo-public --type python --port 8080

# Deploy web server in private subnet  
sudo ./src/vpcctl.py deploy-server --namespace demo-private --type python --port 8080

# Test application connectivity
sudo ./src/vpcctl.py test-connectivity --source demo-public --target demo-private --port 8080
```

### Security Policy Management

#### Individual Security Rules

```bash
# Allow HTTP traffic from public to private subnet
sudo ./src/vpcctl.py add-security-rule \
  --namespace demo-private \
  --protocol tcp \
  --port 80 \
  --source 10.50.0.0/17 \
  --action ACCEPT
```

#### JSON-Based Policies

```bash
# Create comprehensive policy file
cat > /tmp/demo-policy.json << 'EOF'
{
  "subnet": "10.50.0.0/16",
  "ingress": [
    {
      "protocol": "tcp",
      "port": 80,
      "source": "10.50.0.0/17", 
      "action": "allow",
      "description": "Allow HTTP from public subnet"
    },
    {
      "protocol": "tcp",
      "port": 22,
      "source": "0.0.0.0/0",
      "action": "deny",
      "description": "Block all SSH traffic"
    }
  ],
  "egress": [
    {
      "protocol": "tcp",
      "port": "all",
      "destination": "0.0.0.0/0",
      "action": "allow",
      "description": "Allow all outbound TCP"
    }
  ]
}
EOF

# Apply policy to namespace
sudo ./src/vpcctl.py apply-policy --namespace demo-private --policy-file /tmp/demo-policy.json
```

---

## Testing & Validation

### Automated Test Suite

The project includes a comprehensive integration test suite:

```bash
# Run full test suite (recommended)
sudo python3 test_suite.py

# Expected output for each test:
# VPC Creation: PASS ✅
# Internet Connectivity: PASS ✅  
# Private Isolation: PASS ✅
# Inter-subnet Communication: PASS ✅
# VPC Peering Creation: PASS ✅
# Cross-VPC Communication: PASS ✅
# Server Deployment: PASS ✅
# Server Accessibility: PASS ✅
# Policy Application: PASS ✅
# Policy Enforcement: PASS ✅
# Complete Cleanup: PASS ✅
# ALL TESTS PASSED! ✅
```

Using Makefile:

```bash
# Quick test run
sudo make test
```

### Manual Validation Steps

#### 1. VPC Creation Validation

```bash
# Check namespace creation
sudo ip netns list | grep -E "(demo-public|demo-private|demo-nat)"

# Verify bridge exists and is up
ip link show br-demo

# Check interface connections
sudo bridge link show br-demo
```

#### 2. Connectivity Testing

```bash
# Public subnet internet access (should work)
echo "Testing public subnet internet access..."
sudo ip netns exec demo-public curl -s --connect-timeout 5 http://httpbin.org/ip

# Private subnet isolation (should fail)
echo "Testing private subnet isolation..."
timeout 5 sudo ip netns exec demo-private curl -s http://httpbin.org/ip || echo "✓ Correctly isolated"

# Inter-subnet communication (should work)
echo "Testing inter-subnet communication..."
private_ip=$(sudo ip netns exec demo-private ip addr show | grep "inet " | grep -v "127" | awk '{print $2}' | cut -d/ -f1)
sudo ip netns exec demo-public ping -c 2 $private_ip
```

#### 3. NAT Behavior Validation

```bash
# Test source NAT (IP should be different)
echo "Testing NAT behavior..."

# Get internal IP
internal_ip=$(sudo ip netns exec demo-public ip addr show | grep "inet " | grep -v "127" | awk '{print $2}' | cut -d/ -f1)
echo "Internal IP: $internal_ip"

# Get external IP as seen by internet
external_ip=$(sudo ip netns exec demo-public curl -s http://httpbin.org/ip | python3 -c "import sys, json; print(json.load(sys.stdin)['origin'])")
echo "External IP: $external_ip"

# They should be different (NAT working)
if [ "$internal_ip" != "$external_ip" ]; then
    echo "✓ NAT working correctly"
else
    echo "✗ NAT not working"
fi
```

#### 4. Security Rule Validation

```bash
# Test HTTP access (should work with policy)
sudo ip netns exec demo-public curl -s -o /dev/null -w "%{http_code}" http://$private_ip:8080

# Test SSH access (should be blocked)
timeout 3 sudo ip netns exec demo-public nc -zv $private_ip 22 || echo "✓ SSH correctly blocked"
```

---

## Advanced Features

### VPC Peering Configuration

VPC peering allows communication between isolated VPCs:

```bash
# Create two VPCs with non-overlapping CIDRs
sudo ./src/vpcctl.py create-vpc --name vpc-east --cidr 10.1.0.0/16
sudo ./src/vpcctl.py create-vpc --name vpc-west --cidr 10.2.0.0/16

# Establish peering connection
sudo ./src/vpcctl.py create-vpc-peering --vpc1 vpc-east --vpc2 vpc-west

# Test cross-VPC communication
east_ip=$(sudo ip netns exec vpc-east-public ip addr show | grep "inet " | grep -v "127" | awk '{print $2}' | cut -d/ -f1)
sudo ip netns exec vpc-west-public ping -c 3 $east_ip

# Remove peering when done
sudo ./src/vpcctl.py delete-vpc-peering --vpc1 vpc-east --vpc2 vpc-west
```

### Complex Security Policies

```bash
# Multi-tier application policy
cat > /tmp/complex-policy.json << 'EOF'
{
  "subnet": "10.50.128.0/17",
  "ingress": [
    {
      "protocol": "tcp",
      "port": 3306,
      "source": "10.50.0.0/24",
      "action": "allow",
      "description": "Allow MySQL from app tier"
    },
    {
      "protocol": "tcp", 
      "port": 22,
      "source": "10.50.0.10/32",
      "action": "allow",
      "description": "Allow SSH from bastion host"
    },
    {
      "protocol": "icmp",
      "source": "10.50.0.0/17",
      "action": "allow", 
      "description": "Allow ping from public subnet"
    }
  ],
  "egress": [
    {
      "protocol": "tcp",
      "port": 53,
      "destination": "8.8.8.8/32",
      "action": "allow",
      "description": "Allow DNS queries"
    },
    {
      "protocol": "tcp",
      "port": 443,
      "destination": "0.0.0.0/0", 
      "action": "allow",
      "description": "Allow HTTPS outbound"
    }
  ]
}
EOF

sudo ./src/vpcctl.py apply-policy --namespace demo-private --policy-file /tmp/complex-policy.json
```

### Monitoring and Debugging

```bash
# Check VPC status
make status

# Monitor traffic with tcpdump
sudo ip netns exec demo-public tcpdump -i any icmp

# Check iptables rules
sudo ip netns exec demo-private iptables -L -n -v

# Examine bridge forwarding table  
sudo bridge fdb show br-demo

# Check NAT translations
sudo ip netns exec demo-nat iptables -t nat -L -n -v
```

---

## Troubleshooting

### Common Issues and Solutions

#### 1. **"Permission denied" or "Operation not permitted"**

**Problem**: Not running with sufficient privileges

**Solution**:
```bash
# Ensure you're using sudo
sudo ./src/vpcctl.py create-vpc --name test --cidr 10.0.0.0/16

# Check if running as root
id
# Should show uid=0(root)
```

#### 2. **"Network unreachable" from public subnet**

**Problem**: NAT or routing not configured correctly

**Diagnosis**:
```bash
# Check if IP forwarding is enabled
cat /proc/sys/net/ipv4/ip_forward
# Should be 1

# Check NAT namespace routing
sudo ip netns exec demo-nat ip route show

# Check NAT rules
sudo ip netns exec demo-nat iptables -t nat -L -n -v
```

**Solution**:
```bash
# Re-create VPC (cleanup and recreate)
sudo ./src/vpcctl.py delete-vpc --name demo
sudo ./src/vpcctl.py create-vpc --name demo --cidr 10.50.0.0/16
```

#### 3. **"Address already in use" errors**

**Problem**: Conflicting network resources

**Solution**:
```bash
# Run comprehensive cleanup
sudo ./cleanup.sh

# Check for remaining resources
sudo ip netns list
sudo ip link show type bridge
```

#### 4. **Cross-VPC communication fails**

**Problem**: Peering configuration or routing issues

**Diagnosis**:
```bash
# Check peering interface exists
sudo ip link show | grep -E "(vpc1-to-vpc2|vpc2-to-vpc1)"

# Check cross-VPC routes
sudo ip netns exec vpc1-public ip route show | grep vpc2
```

#### 5. **Security policies not working**

**Problem**: iptables rules not applied correctly

**Diagnosis**:
```bash
# Check current rules
sudo ip netns exec demo-private iptables -L -n --line-numbers

# Verify rule order (first match wins)
sudo ip netns exec demo-private iptables -L INPUT -n -v
```

### Debug Mode

Enable detailed logging for troubleshooting:

```bash
# Set debug logging
export PYTHONPATH=/path/to/network-in-a-box/src
export NETWORK_DEBUG=1

# Run with verbose output
sudo -E ./src/vpcctl.py create-vpc --name debug-vpc --cidr 10.99.0.0/16
```

---

## Cleanup & Resource Management

### Quick Cleanup

```bash
# Remove specific VPC
sudo ./src/vpcctl.py delete-vpc --name demo

# Remove multiple VPCs
sudo ./src/vpcctl.py delete-vpc --name production --name demo

# Verify cleanup
sudo ip netns list | grep -E "(demo|production)"  # Should be empty
```

### Comprehensive Cleanup

The project includes a comprehensive cleanup script:

```bash
# Standard cleanup (removes all test/VPC resources)
sudo ./cleanup.sh

# Aggressive cleanup (includes sysctl reset)
sudo ./cleanup.sh --reset-sysctl

# Using Makefile
sudo make clean-all
```

### Manual Cleanup (if needed)

```bash
# Remove all VPC namespaces
for ns in $(sudo ip netns list | grep -E "(public|private|nat)$" | awk '{print $1}'); do
    sudo ip netns del "$ns"
done

# Remove all VPC bridges
for br in $(ip link show type bridge | grep "br-" | cut -d: -f2 | tr -d ' '); do
    sudo ip link del "$br"
done

# Clean iptables NAT rules
sudo iptables -t nat -F
sudo iptables -F FORWARD

# Remove state file
sudo rm -f /var/tmp/network_in_a_box.state
```

### Verify Clean State

```bash
# Check no VPC resources remain
echo "=== Cleanup Verification ==="
echo "Namespaces: $(sudo ip netns list | grep -E "(public|private|nat)" | wc -l)"
echo "Bridges: $(ip link show type bridge | grep -c "br-")"
echo "State file: $([ -f /var/tmp/network_in_a_box.state ] && echo "Present" || echo "Removed")"
```

---

## Next Steps

### Extending the Project

#### 1. **Add More Cloud Features**
- **Route Tables**: Implement custom routing tables
- **Internet Gateways**: Separate IGW from NAT functionality
- **Load Balancers**: Add layer 4/7 load balancing
- **DNS Resolution**: Internal DNS for service discovery

#### 2. **Monitoring and Observability**
- **Metrics Collection**: Network statistics and performance metrics
- **Logging**: Centralized logging for all network events
- **Alerting**: Monitor for configuration drift or failures
- **Dashboards**: Web-based visualization of network topology

#### 3. **Automation and Orchestration**
- **Configuration Management**: Ansible/Terraform integration
- **CI/CD Integration**: Automated testing in pipelines
- **API Server**: REST API for programmatic management
- **Container Integration**: Docker/Kubernetes networking

#### 4. **Security Enhancements**
- **Network Segmentation**: Micro-segmentation policies
- **Traffic Analysis**: Deep packet inspection
- **Threat Detection**: Anomaly detection in network traffic
- **Compliance**: PCI/SOX compliance features

### Learning Path

#### Beginner → Intermediate
1. **Master the Basics**: Create/delete VPCs, understand routing
2. **Security Configuration**: Complex policy management
3. **Multi-VPC Scenarios**: Peering and isolation patterns
4. **Troubleshooting**: Debug connectivity issues

#### Intermediate → Advanced  
1. **Protocol Deep Dives**: TCP/IP, BGP, OSPF simulation
2. **Performance Optimization**: Latency and throughput tuning
3. **Scalability Testing**: Large-scale VPC deployments
4. **Integration Projects**: Connect with real cloud providers

### Recommended Resources

#### Books
- **"TCP/IP Illustrated"** by Richard Stevens
- **"Computer Networks"** by Andrew Tanenbaum
- **"Linux Network Administrator's Guide"** by Terry Dawson

#### Online Resources
- **Linux Networking Documentation**: kernel.org networking docs
- **AWS VPC Guide**: Understanding real-world VPC concepts
- **Netfilter/iptables Documentation**: Advanced firewall configuration
- **Network Namespace Tutorial**: Deep dive into Linux namespaces

#### Practice Projects
- **Build a Software Router**: Using Linux and FRRouting
- **Implement BGP**: Route advertisement between VPCs
- **Create a Firewall**: Advanced iptables/nftables configuration
- **Network Monitoring**: Implement traffic analysis tools

---

## Conclusion

Congratulations! You've successfully built and deployed your own VPC simulation system. You now understand:

✅ **VPC Architecture**: How cloud networking works under the hood  
✅ **Linux Networking**: Namespaces, bridges, routing, and NAT  
✅ **Security Groups**: Policy-based network access control  
✅ **Automation**: CLI tools and infrastructure as code  
✅ **Testing**: Validation and troubleshooting techniques  

### Key Takeaways

1. **Cloud Networking Demystified**: You've seen exactly how VPCs work internally
2. **Linux Networking Mastery**: Practical experience with advanced networking concepts  
3. **Infrastructure as Code**: Built automation tools for network management
4. **Security Best Practices**: Implemented defense-in-depth networking security
5. **Testing Methodology**: Created comprehensive validation procedures

### Real-World Applications

This knowledge directly applies to:
- **Cloud Architecture Design**: Better understanding of AWS/Azure/GCP networking
- **DevOps Engineering**: Network automation and infrastructure management
- **Security Engineering**: Network segmentation and access control
- **Site Reliability Engineering**: Troubleshooting complex networking issues

The Network-in-a-Box project provides a solid foundation for understanding modern cloud networking. Use this knowledge to build more sophisticated systems, contribute to open-source networking projects, or advance your career in cloud infrastructure.

**Happy Networking!** 🌐🚀

---

*Did you find this tutorial helpful? Star the repository and share your experience! Have questions or improvements? Open an issue or contribute to the project.*

**Repository**: [Network-in-a-Box on GitHub](https://github.com/yourusername/network-in-a-box)  
**Documentation**: [Complete API Reference](docs/)  
**Support**: [Issue Tracker](https://github.com/yourusername/network-in-a-box/issues)