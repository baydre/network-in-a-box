#!/usr/bin/env python3
"""
Comprehensive integration test suite for Network-in-a-Box
Tests all major functionality including VPC creation, peering, NAT, security groups, etc.
"""

import subprocess
import sys
import time
import json
import logging
from typing import Dict, List, Tuple

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class NetworkTestSuite:
    def __init__(self):
        self.vpcctl_path = "./src/vpcctl.py"
        self.test_vpcs = ["test-vpc1", "test-vpc2"]
        self.test_cidrs = ["10.1.0.0/16", "10.2.0.0/16"]
        self.results = []

    def run_command(self, cmd: List[str], check: bool = True) -> subprocess.CompletedProcess:
        """Execute a command and return the result."""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=check)
            return result
        except subprocess.CalledProcessError as e:
            if check:
                logger.error(f"Command failed: {' '.join(cmd)}")
                logger.error(f"Error: {e.stderr}")
                raise
            return e

    def test_result(self, test_name: str, passed: bool, details: str = "") -> None:
        """Record a test result."""
        status = "PASS" if passed else "FAIL"
        self.results.append({"test": test_name, "status": status, "details": details})
        logger.info(f"{test_name}: {status} {details}")

    def cleanup_test_vpcs(self) -> None:
        """Clean up any existing test VPCs."""
        logger.info("Cleaning up existing test VPCs...")
        for vpc_name in self.test_vpcs:
            try:
                self.run_command(["sudo", self.vpcctl_path, "delete-vpc", "--name", vpc_name], check=False)
            except:
                pass

    def test_vpc_creation(self) -> bool:
        """Test VPC creation and basic infrastructure."""
        logger.info("Testing VPC creation...")
        
        try:
            # Create test VPCs
            for i, vpc_name in enumerate(self.test_vpcs):
                result = self.run_command([
                    "sudo", self.vpcctl_path, "create-vpc", 
                    "--name", vpc_name, "--cidr", self.test_cidrs[i]
                ])
                
                if result.returncode != 0:
                    self.test_result("VPC Creation", False, f"Failed to create {vpc_name}")
                    return False

            # Verify namespaces were created
            result = self.run_command(["sudo", "ip", "netns", "list"])
            namespaces = result.stdout
            
            expected_ns = []
            for vpc in self.test_vpcs:
                expected_ns.extend([f"{vpc}-public", f"{vpc}-private", f"{vpc}-nat"])
            
            missing_ns = [ns for ns in expected_ns if ns not in namespaces]
            if missing_ns:
                self.test_result("VPC Creation", False, f"Missing namespaces: {missing_ns}")
                return False

            # Verify bridges were created  
            result = self.run_command(["ip", "link", "show", "type", "bridge"])
            bridges = result.stdout
            
            expected_bridges = [f"br-{vpc}" for vpc in self.test_vpcs]
            missing_bridges = [br for br in expected_bridges if br not in bridges]
            if missing_bridges:
                self.test_result("VPC Creation", False, f"Missing bridges: {missing_bridges}")
                return False

            self.test_result("VPC Creation", True, f"Created {len(self.test_vpcs)} VPCs with all components")
            return True
            
        except Exception as e:
            self.test_result("VPC Creation", False, f"Exception: {str(e)}")
            return False

    def test_vpc_connectivity(self) -> bool:
        """Test intra-VPC and internet connectivity."""
        logger.info("Testing VPC connectivity...")
        
        try:
            vpc1 = self.test_vpcs[0]
            
            # Test public subnet internet access
            result = self.run_command([
                "sudo", "ip", "netns", "exec", f"{vpc1}-public",
                "ping", "-c", "2", "-W", "3", "8.8.8.8"
            ], check=False)
            
            if result.returncode != 0:
                self.test_result("Internet Connectivity", False, "Public subnet cannot reach internet")
                return False
            else:
                self.test_result("Internet Connectivity", True, "Public subnet has internet access")

            # Test private subnet isolation (should fail)
            result = self.run_command([
                "sudo", "ip", "netns", "exec", f"{vpc1}-private",
                "ping", "-c", "1", "-W", "2", "8.8.8.8"
            ], check=False)
            
            if result.returncode == 0:
                self.test_result("Private Isolation", False, "Private subnet has internet access (should be blocked)")
                return False
            else:
                self.test_result("Private Isolation", True, "Private subnet is properly isolated")

            # Test inter-subnet communication within VPC
            # Get the correct interface name using the same logic as vpcctl
            import hashlib
            clean_name = ''.join(ch for ch in vpc1 if ch.isalnum()).lower()[:4]
            hash_hex = hashlib.md5(vpc1.encode()).hexdigest()[:4]
            iface_tag = f"{clean_name}{hash_hex}"
            
            # Get private subnet IP
            result = self.run_command([
                "sudo", "ip", "netns", "exec", f"{vpc1}-private",
                "ip", "addr", "show", f"vn{iface_tag}r"
            ])
            
            # Extract IP address (simplified - look for inet line)
            lines = result.stdout.split('\n')
            private_ip = None
            for line in lines:
                if 'inet ' in line and '127.0.0.1' not in line:
                    private_ip = line.split()[1].split('/')[0]
                    break
            
            if not private_ip:
                self.test_result("Inter-subnet Communication", False, "Could not find private subnet IP")
                return False

            # Test ping from public to private
            result = self.run_command([
                "sudo", "ip", "netns", "exec", f"{vpc1}-public",
                "ping", "-c", "2", "-W", "3", private_ip
            ], check=False)
            
            if result.returncode == 0:
                self.test_result("Inter-subnet Communication", True, f"Public can reach private subnet at {private_ip}")
            else:
                self.test_result("Inter-subnet Communication", False, f"Cannot reach private subnet at {private_ip}")
                return False

            return True
            
        except Exception as e:
            self.test_result("VPC Connectivity", False, f"Exception: {str(e)}")
            return False

    def test_vpc_peering(self) -> bool:
        """Test VPC peering functionality."""
        logger.info("Testing VPC peering...")
        
        try:
            vpc1, vpc2 = self.test_vpcs[0], self.test_vpcs[1]
            
            # Create peering connection
            result = self.run_command([
                "sudo", self.vpcctl_path, "create-vpc-peering",
                "--vpc1", vpc1, "--vpc2", vpc2
            ])
            
            if result.returncode != 0:
                self.test_result("VPC Peering Creation", False, "Failed to create peering connection")
                return False
            else:
                self.test_result("VPC Peering Creation", True, "Peering connection created successfully")

            # Wait a moment for routes to settle
            time.sleep(2)

            # Test cross-VPC connectivity
            # Get IP of vpc2 public subnet using correct interface naming
            import hashlib
            clean_name2 = ''.join(ch for ch in vpc2 if ch.isalnum()).lower()[:4]
            hash_hex2 = hashlib.md5(vpc2.encode()).hexdigest()[:4]
            iface_tag2 = f"{clean_name2}{hash_hex2}"
            
            result = self.run_command([
                "sudo", "ip", "netns", "exec", f"{vpc2}-public",
                "ip", "addr", "show", f"vn{iface_tag2}p"
            ])
            
            # Extract IP address
            lines = result.stdout.split('\n')
            vpc2_ip = None
            for line in lines:
                if 'inet ' in line and '127.0.0.1' not in line:
                    vpc2_ip = line.split()[1].split('/')[0]
                    break
            
            if not vpc2_ip:
                self.test_result("Cross-VPC Communication", False, "Could not find VPC2 public IP")
                return False

            # Test ping from vpc1 to vpc2
            result = self.run_command([
                "sudo", "ip", "netns", "exec", f"{vpc1}-public",
                "ping", "-c", "2", "-W", "3", vpc2_ip
            ], check=False)
            
            if result.returncode == 0:
                self.test_result("Cross-VPC Communication", True, f"VPC1 can reach VPC2 at {vpc2_ip}")
            else:
                self.test_result("Cross-VPC Communication", False, f"Cannot reach VPC2 at {vpc2_ip}")
                return False

            return True
            
        except Exception as e:
            self.test_result("VPC Peering", False, f"Exception: {str(e)}")
            return False

    def test_server_deployment(self) -> bool:
        """Test server deployment and connectivity."""
        logger.info("Testing server deployment...")
        
        try:
            vpc1 = self.test_vpcs[0]
            
            # Deploy server
            result = self.run_command([
                "sudo", self.vpcctl_path, "deploy-server",
                "--namespace", f"{vpc1}-public", "--type", "python", "--port", "8080"
            ])
            
            if result.returncode != 0:
                self.test_result("Server Deployment", False, "Failed to deploy test server")
                return False
            else:
                self.test_result("Server Deployment", True, "Test server deployed successfully")

            # Wait for server to start
            time.sleep(3)

            # Test server accessibility from same VPC
            # Get the actual IP from the namespace instead of guessing
            import hashlib
            clean_name = ''.join(ch for ch in vpc1 if ch.isalnum()).lower()[:4]
            hash_hex = hashlib.md5(vpc1.encode()).hexdigest()[:4]
            iface_tag = f"{clean_name}{hash_hex}"
            
            result = self.run_command([
                "sudo", "ip", "netns", "exec", f"{vpc1}-public",
                "ip", "addr", "show", f"vn{iface_tag}p"
            ])
            
            # Extract the actual IP address
            lines = result.stdout.split('\n')
            vpc1_public_ip = None
            for line in lines:
                if 'inet ' in line and '127.0.0.1' not in line:
                    vpc1_public_ip = line.split()[1].split('/')[0]
                    break
            
            if not vpc1_public_ip:
                self.test_result("Server Accessibility", False, "Could not find public subnet IP for server test")
                return False
            
            result = self.run_command([
                "sudo", "ip", "netns", "exec", f"{vpc1}-private",
                "curl", "-s", "--connect-timeout", "5", f"http://{vpc1_public_ip}:8080"
            ], check=False)
            
            if result.returncode == 0 and "Hello from" in result.stdout:
                self.test_result("Server Accessibility", True, f"Server responds: {result.stdout.strip()}")
            else:
                self.test_result("Server Accessibility", False, f"Server not accessible or wrong response")
                return False

            return True
            
        except Exception as e:
            self.test_result("Server Deployment", False, f"Exception: {str(e)}")
            return False

    def test_security_policies(self) -> bool:
        """Test security policy application."""
        logger.info("Testing security policies...")
        
        try:
            vpc1 = self.test_vpcs[0]
            
            # Get the server IP first
            import hashlib
            clean_name = ''.join(ch for ch in vpc1 if ch.isalnum()).lower()[:4]
            hash_hex = hashlib.md5(vpc1.encode()).hexdigest()[:4]
            iface_tag = f"{clean_name}{hash_hex}"
            
            result = self.run_command([
                "sudo", "ip", "netns", "exec", f"{vpc1}-public",
                "ip", "addr", "show", f"vn{iface_tag}p"
            ])
            
            # Extract the actual IP address
            lines = result.stdout.split('\n')
            vpc1_public_ip = None
            for line in lines:
                if 'inet ' in line and '127.0.0.1' not in line:
                    vpc1_public_ip = line.split()[1].split('/')[0]
                    break
            
            if not vpc1_public_ip:
                self.test_result("Security Policies", False, "Could not find public IP for policy test")
                return False
            
            # Create a policy file that blocks HTTP
            policy = {
                "subnet": self.test_cidrs[0],
                "ingress": [
                    {
                        "port": 8080,
                        "protocol": "tcp",
                        "source": "0.0.0.0/0",
                        "action": "deny",
                        "description": "Block HTTP on 8080"
                    }
                ],
                "egress": [
                    {
                        "port": "all",
                        "protocol": "all", 
                        "destination": "0.0.0.0/0",
                        "action": "allow",
                        "description": "Allow all outbound"
                    }
                ]
            }
            
            # Write policy file
            with open("/tmp/test-block-policy.json", "w") as f:
                json.dump(policy, f, indent=2)

            # Apply policy
            result = self.run_command([
                "sudo", self.vpcctl_path, "apply-policy",
                "--namespace", f"{vpc1}-public", 
                "--policy-file", "/tmp/test-block-policy.json"
            ])
            
            if result.returncode != 0:
                self.test_result("Policy Application", False, "Failed to apply security policy")
                return False
            else:
                self.test_result("Policy Application", True, "Security policy applied successfully")

            # Wait for policy to take effect
            time.sleep(2)

            # Test that server is now blocked from different VPC
            # Use the same IP we got earlier
            result = self.run_command([
                "sudo", "ip", "netns", "exec", f"{self.test_vpcs[1]}-public",
                "curl", "-s", "--connect-timeout", "3", f"http://{vpc1_public_ip}:8080"
            ], check=False)
            
            if result.returncode != 0:
                self.test_result("Policy Enforcement", True, "HTTP traffic successfully blocked by policy")
            else:
                self.test_result("Policy Enforcement", False, f"Policy not enforced - got response: {result.stdout}")
                return False

            return True
            
        except Exception as e:
            self.test_result("Security Policies", False, f"Exception: {str(e)}")
            return False

    def test_cleanup(self) -> bool:
        """Test VPC deletion and cleanup."""
        logger.info("Testing cleanup...")
        
        try:
            # Delete peering first
            result = self.run_command([
                "sudo", self.vpcctl_path, "delete-vpc-peering",
                "--vpc1", self.test_vpcs[0], "--vpc2", self.test_vpcs[1]
            ], check=False)
            
            # Delete VPCs
            for vpc_name in self.test_vpcs:
                result = self.run_command([
                    "sudo", self.vpcctl_path, "delete-vpc", "--name", vpc_name
                ], check=False)
                
                if result.returncode != 0:
                    self.test_result("VPC Deletion", False, f"Failed to delete {vpc_name}")
                    return False

            # Verify namespaces are gone
            result = self.run_command(["sudo", "ip", "netns", "list"])
            namespaces = result.stdout
            
            remaining_test_ns = []
            for vpc in self.test_vpcs:
                test_ns = [f"{vpc}-public", f"{vpc}-private", f"{vpc}-nat"]
                remaining_test_ns.extend([ns for ns in test_ns if ns in namespaces])
            
            if remaining_test_ns:
                self.test_result("Namespace Cleanup", False, f"Namespaces not cleaned: {remaining_test_ns}")
                return False
            else:
                self.test_result("Namespace Cleanup", True, "All test namespaces cleaned up")

            # Verify bridges are gone
            result = self.run_command(["ip", "link", "show", "type", "bridge"])
            bridges = result.stdout
            
            remaining_bridges = [f"br-{vpc}" for vpc in self.test_vpcs if f"br-{vpc}" in bridges]
            if remaining_bridges:
                self.test_result("Bridge Cleanup", False, f"Bridges not cleaned: {remaining_bridges}")
                return False
            else:
                self.test_result("Bridge Cleanup", True, "All test bridges cleaned up")

            self.test_result("Complete Cleanup", True, "All resources cleaned up successfully")
            return True
            
        except Exception as e:
            self.test_result("Cleanup", False, f"Exception: {str(e)}")
            return False

    def run_all_tests(self) -> bool:
        """Run the complete test suite."""
        logger.info("Starting Network-in-a-Box Integration Test Suite")
        logger.info("=" * 60)
        
        # Initial cleanup
        self.cleanup_test_vpcs()
        
        tests = [
            self.test_vpc_creation,
            self.test_vpc_connectivity,
            self.test_vpc_peering,
            self.test_server_deployment,
            self.test_security_policies,
            self.test_cleanup
        ]
        
        all_passed = True
        for test in tests:
            try:
                if not test():
                    all_passed = False
                    logger.error(f"Test {test.__name__} failed!")
            except Exception as e:
                logger.error(f"Test {test.__name__} crashed: {str(e)}")
                all_passed = False
            
            time.sleep(1)  # Brief pause between tests
        
        return all_passed

    def print_summary(self) -> None:
        """Print test results summary."""
        logger.info("=" * 60)
        logger.info("TEST RESULTS SUMMARY")
        logger.info("=" * 60)
        
        passed = sum(1 for result in self.results if result["status"] == "PASS")
        failed = sum(1 for result in self.results if result["status"] == "FAIL")
        
        for result in self.results:
            status = result["status"]
            details = result["details"]
            symbol = "✅" if status == "PASS" else "❌"
            logger.info(f"{symbol} {result['test']}: {status} {details}")
        
        logger.info("-" * 60)
        logger.info(f"Total Tests: {len(self.results)}")
        logger.info(f"Passed: {passed}")
        logger.info(f"Failed: {failed}")
        logger.info(f"Success Rate: {(passed/len(self.results)*100):.1f}%" if self.results else "0%")
        
        if failed == 0:
            logger.info("🎉 ALL TESTS PASSED! Network-in-a-Box is working correctly!")
        else:
            logger.error(f"⚠️  {failed} tests failed. Please review the implementation.")

def main():
    """Main entry point for the test suite."""
    test_suite = NetworkTestSuite()
    
    try:
        success = test_suite.run_all_tests()
        test_suite.print_summary()
        
        sys.exit(0 if success else 1)
        
    except KeyboardInterrupt:
        logger.info("Test suite interrupted by user")
        test_suite.cleanup_test_vpcs()
        sys.exit(130)
    except Exception as e:
        logger.error(f"Test suite crashed: {str(e)}")
        test_suite.cleanup_test_vpcs()
        sys.exit(1)

if __name__ == "__main__":
    main()