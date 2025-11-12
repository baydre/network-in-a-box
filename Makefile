# Network-in-a-Box Makefile
# Quick setup and management commands

.PHONY: help install test clean setup deps validate

# Default target
help:
	@echo "Network-in-a-Box - VPC Simulation Tool"
	@echo "======================================="
	@echo ""
	@echo "Available commands:"
	@echo "  make install      - Install system dependencies"
	@echo "  make setup        - Setup development environment"
	@echo "  make test         - Run integration test suite"
	@echo "  make quick-demo   - Run 5-minute demo (all scenarios)"
	@echo "  make full-demo    - Run complete 15-minute demo"
	@echo "  make validate     - Validate system requirements"
	@echo "  make clean        - Clean up test resources"
	@echo "  make clean-all    - Complete cleanup including logs"
	@echo ""
	@echo "Quick Start:"
	@echo "  1. make install"
	@echo "  2. make setup"
	@echo "  3. make quick-demo"
	@echo ""

# Install system dependencies
install:
	@echo "Installing system dependencies..."
	sudo apt-get update
	sudo apt-get install -y iproute2 iptables bridge-utils curl python3 python3-pip
	@echo "System dependencies installed successfully!"

# Setup development environment
setup:
	@echo "Setting up Network-in-a-Box environment..."
	@chmod +x src/vpcctl.py
	@chmod +x cleanup.sh
	@echo "Validating system requirements..."
	@$(MAKE) validate
	@echo "Environment setup complete!"

# Validate system requirements
validate:
	@echo "Validating system requirements..."
	@echo -n "Checking root access: "
	@if [ "$$(id -u)" -eq 0 ]; then echo "✓ OK"; else echo "✗ FAIL - Run with sudo"; exit 1; fi
	@echo -n "Checking ip command: "
	@if command -v ip >/dev/null 2>&1; then echo "✓ OK"; else echo "✗ FAIL - Install iproute2"; exit 1; fi
	@echo -n "Checking iptables: "
	@if command -v iptables >/dev/null 2>&1; then echo "✓ OK"; else echo "✗ FAIL - Install iptables"; exit 1; fi
	@echo -n "Checking bridge utils: "
	@if command -v brctl >/dev/null 2>&1; then echo "✓ OK"; else echo "✗ FAIL - Install bridge-utils"; exit 1; fi
	@echo -n "Checking curl: "
	@if command -v curl >/dev/null 2>&1; then echo "✓ OK"; else echo "✗ FAIL - Install curl"; exit 1; fi
	@echo -n "Checking Python 3: "
	@if command -v python3 >/dev/null 2>&1; then echo "✓ OK"; else echo "✗ FAIL - Install python3"; exit 1; fi
	@echo "All requirements satisfied!"

# Run integration test suite
test:
	@echo "Running Network-in-a-Box test suite..."
	@if [ "$$(id -u)" -ne 0 ]; then echo "Error: Tests must be run as root"; exit 1; fi
	sudo python3 test_suite.py
	@echo "Test suite completed!"

# Run quick 5-minute demo
quick-demo:
	@echo "Running 5-minute demonstration..."
	@if [ "$$(id -u)" -ne 0 ]; then echo "Error: Demo must be run as root"; exit 1; fi
	sudo ./quick_demo.sh
	@echo "Quick demo completed!"

# Run full demo
full-demo:
	@echo "Running full demonstration..."
	@if [ "$$(id -u)" -ne 0 ]; then echo "Error: Demo must be run as root"; exit 1; fi
	sudo ./demo_script.sh --auto
	@echo "Full demo completed!"

# Clean up test resources
clean:
	@echo "Cleaning up test resources..."
	sudo ./cleanup.sh
	@echo "Cleanup completed!"

# Complete cleanup including logs
clean-all: clean
	@echo "Performing complete cleanup..."
	sudo rm -f /var/tmp/network_in_a_box.state
	sudo rm -f /tmp/test-*.json
	@echo "Complete cleanup finished!"

# Create a demo VPC
demo:
	@echo "Creating demo VPC..."
	@if [ "$$(id -u)" -ne 0 ]; then echo "Error: Must be run as root"; exit 1; fi
	sudo ./src/vpcctl.py create-vpc --name demo --cidr 10.50.0.0/16
	@echo "Demo VPC created! Try:"
	@echo "  sudo ip netns exec demo-public ping -c 3 8.8.8.8"
	@echo "  sudo ./src/vpcctl.py deploy-server --namespace demo-public --type python --port 8080"

# Remove demo VPC
demo-clean:
	@echo "Removing demo VPC..."
	sudo ./src/vpcctl.py delete-vpc --name demo
	@echo "Demo VPC removed!"

# Show VPC status
status:
	@echo "Network-in-a-Box Status:"
	@echo "========================"
	@echo "Active namespaces:"
	@sudo ip netns list | grep -E "(public|private|nat)" || echo "  None"
	@echo ""
	@echo "Active bridges:"
	@ip link show type bridge | grep -E "^[0-9]+:" | cut -d: -f2 | grep "br-" || echo "  None"
	@echo ""
	@echo "State file:"
	@if [ -f /var/tmp/network_in_a_box.state ]; then echo "  ✓ Present"; else echo "  ✗ Not found"; fi