#!/usr/bin/env python3

import ipaddress
import json
import logging
import subprocess
import time
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

class NetworkValidator:
    """Network state validation and diagnostic tool."""
    
    def __init__(self):
        self.debug = True
        self._vpc_cidrs = {}
    
    def execute_command(self, command: List[str], check: bool = True, 
                       namespace: Optional[str] = None) -> subprocess.CompletedProcess:
        """Execute a command and return its output."""
        if namespace:
            command = ["ip", "netns", "exec", namespace] + command
            
        try:
            result = subprocess.run(command, check=check, 
                                  capture_output=True, text=True)
            return result
        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed: {e.cmd}")
            logger.error(f"Error output: {e.stderr}")
            if check:
                raise
            return e
    
    def check_interface(self, name: str, namespace: Optional[str] = None) -> Dict:
        """Check interface configuration and state."""
        cmd = ["ip", "addr", "show", "dev", name]
        result = self.execute_command(cmd, namespace=namespace, check=False)
        
        # Parse interface info
        info = {
            "exists": result.returncode == 0,
            "state": "DOWN",
            "addresses": []
        }
        
        if result.returncode == 0:
            for line in result.stdout.split("\n"):
                logger.debug(f"Interface line: {line}")
                if "state UP" in line:
                    info["state"] = "UP"
                elif "inet " in line:
                    addr = line.strip().split()[1]
                    info["addresses"].append(addr)
                    info["state"] = "UP"  # If it has an IP, consider it up
        
        return info
    
    def check_bridge(self, name: str) -> Dict:
        """Check bridge configuration and connected interfaces."""
        info = self.check_interface(name)
        
        # Get bridge-specific info
        if info["exists"]:
            # Check bridge forward delay
            try:
                with open(f"/sys/class/net/{name}/bridge/forward_delay") as f:
                    info["forward_delay"] = f.read().strip()
            except:
                info["forward_delay"] = "unknown"
            
            # Check connected interfaces
            cmd = ["ip", "link", "show", "master", name]
            result = self.execute_command(cmd, check=False)
            info["connected_interfaces"] = []
            
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if "@" in line:
                        iface = line.split("@")[0].split()[-1]
                        info["connected_interfaces"].append(iface)
        
        return info
    
    def check_namespace(self, name: str) -> Dict:
        """Check namespace configuration and interfaces."""
        cmd = ["ip", "netns", "list"]
        result = self.execute_command(cmd)
        
        info = {
            "exists": False,
            "interfaces": [],
            "routes": []
        }
        
        for line in result.stdout.split("\n"):
            if name in line:
                info["exists"] = True
                break
        
        if info["exists"]:
            # Check interfaces
            cmd = ["ip", "link", "show"]
            result = self.execute_command(cmd, namespace=name)
            for line in result.stdout.split("\n"):
                if "@" in line:
                    iface = line.split("@")[0].split()[-1]
                    if iface != "lo":
                        info["interfaces"].append(iface)
            
            # Check routes
            cmd = ["ip", "route", "show"]
            result = self.execute_command(cmd, namespace=name)
            info["routes"] = [line.strip() for line in result.stdout.split("\n") if line.strip()]
        
        return info
    
    def check_connectivity(self, source_ns: str, target_ip: str, 
                         count: int = 1, verbose: bool = True) -> Tuple[bool, str]:
        """Test connectivity between namespace and target IP."""
        cmd = ["ping", "-c", str(count), target_ip]
        if verbose:
            logger.info(f"Testing connectivity from {source_ns} to {target_ip}")
        
        result = self.execute_command(cmd, namespace=source_ns, check=False)
        success = "0% packet loss" in result.stdout
        
        return success, result.stdout if verbose else ""
    
    def check_forwarding(self) -> Dict:
        """Check IP forwarding configuration."""
        info = {}
        
        # Check global forwarding
        try:
            with open("/proc/sys/net/ipv4/ip_forward") as f:
                info["global_forwarding"] = f.read().strip() == "1"
        except:
            info["global_forwarding"] = False
        
        # Check bridge forwarding
        cmd = ["sysctl", "net.bridge.bridge-nf-call-iptables"]
        result = self.execute_command(cmd, check=False)
        info["bridge_forwarding"] = "= 1" in result.stdout if result.returncode == 0 else False
        
        return info
    
    def validate_vpc(self, name: str, vpc_cidr: str) -> Dict:
        """Validate complete VPC configuration."""
        validation = {
            "name": name,
            "vpc_cidr": vpc_cidr,
            "status": "validating",
            "bridge": {},
            "public_namespace": {},
            "private_namespace": {},
            "connectivity": {},
            "forwarding": {},
            "errors": []
        }
        
        try:
            # Check bridge
            bridge_name = f"br-{name}"
            validation["bridge"] = self.check_bridge(bridge_name)
            if not validation["bridge"]["exists"]:
                fallback_bridge = f"{name}-bridge"
                validation["bridge"] = self.check_bridge(fallback_bridge)
                bridge_name = fallback_bridge
            
            # Check namespaces
            public_ns = f"{name}-public"
            private_ns = f"{name}-private"
            validation["public_namespace"] = self.check_namespace(public_ns)
            validation["private_namespace"] = self.check_namespace(private_ns)
            nat_ns = f"{name}-nat"
            validation["nat_namespace"] = self.check_namespace(nat_ns)
            
            # Check forwarding configuration
            validation["forwarding"] = self.check_forwarding()
            
            # Test connectivity
            if validation["public_namespace"]["exists"] and validation["private_namespace"]["exists"]:
                # Get IPs from route tables
                public_ip = None
                private_ip = None
                
                for route in validation["public_namespace"]["routes"]:
                    if "src" in route:
                        public_ip = route.split("src")[1].strip()
                        break
                
                for route in validation["private_namespace"]["routes"]:
                    if "src" in route:
                        private_ip = route.split("src")[1].strip()
                        break
                
                if public_ip and private_ip:
                    # Test both directions
                    pub_to_priv, details = self.check_connectivity(public_ns, private_ip)
                    priv_to_pub, _ = self.check_connectivity(private_ns, public_ip)
                    
                    validation["connectivity"] = {
                        "public_to_private": pub_to_priv,
                        "private_to_public": priv_to_pub,
                        "details": details if self.debug else ""
                    }
            
            # Final status
            if not validation["bridge"]["exists"]:
                validation["errors"].append("Bridge does not exist")
            if not validation["public_namespace"]["exists"]:
                validation["errors"].append("Public namespace does not exist")
            if not validation["private_namespace"]["exists"]:
                validation["errors"].append("Private namespace does not exist")
            if not validation["nat_namespace"]["exists"]:
                validation["errors"].append("NAT namespace does not exist")
            if not validation["forwarding"]["global_forwarding"]:
                validation["errors"].append("Global IP forwarding is disabled")
            
            validation["status"] = "failed" if validation["errors"] else "success"
            
        except Exception as e:
            validation["status"] = "error"
            validation["errors"].append(str(e))
        
        return validation

    def print_validation_report(self, validation: Dict):
        """Print a formatted validation report."""
        print("\n=== VPC Validation Report ===")
        print(f"VPC Name: {validation['name']}")
        print(f"CIDR: {validation['vpc_cidr']}")
        print(f"Status: {validation['status']}")
        
        print("\nBridge Configuration:")
        print(json.dumps(validation['bridge'], indent=2))
        
        print("\nNamespace Configuration:")
        print("Public Namespace:")
        print(json.dumps(validation['public_namespace'], indent=2))
        print("\nPrivate Namespace:")
        print(json.dumps(validation['private_namespace'], indent=2))
        if validation.get('nat_namespace'):
            print("\nNAT Namespace:")
            print(json.dumps(validation['nat_namespace'], indent=2))
        
        print("\nForwarding Configuration:")
        print(json.dumps(validation['forwarding'], indent=2))
        
        if validation.get('connectivity'):
            print("\nConnectivity Tests:")
            print(json.dumps(validation['connectivity'], indent=2))
        
        if validation['errors']:
            print("\nErrors:")
            for error in validation['errors']:
                print(f"- {error}")
        
        print("\n=== End Report ===\n")
    
    def validate_vpc_isolation(self, vpc1: str, vpc2: str) -> Tuple[bool, Optional[str]]:
        """Validate that two VPCs are properly isolated"""
        try:
            vpc1_validation = self.validate_vpc(vpc1, "")  # CIDR not needed for this check
            vpc2_validation = self.validate_vpc(vpc2, "")
            
            if vpc1_validation["status"] != "success":
                return False, f"VPC {vpc1} is not properly configured"
            if vpc2_validation["status"] != "success":
                return False, f"VPC {vpc2} is not properly configured"
            
            # Check if there's a peering connection
            peer1 = f"{vpc1}-to-{vpc2}"
            peer2 = f"{vpc2}-to-{vpc1}"
            result = self.execute_command(["ip", "link", "show"], check=False)
            has_peering = peer1 in result.stdout or peer2 in result.stdout
            
            if has_peering:
                logger.info("VPCs have active peering - testing connectivity")
                # Test connectivity between public namespaces
                vpc1_ip = self._get_namespace_ip(f"{vpc1}-public")
                vpc2_ip = self._get_namespace_ip(f"{vpc2}-public")
                if vpc1_ip and vpc2_ip:
                    success, _ = self.check_connectivity(f"{vpc1}-public", vpc2_ip, verbose=False)
                    if success:
                        return False, "VPCs are not properly isolated - peering allows connectivity"
            
            # If no peering or peering doesn't work, verify isolation
            logger.info("Testing VPC isolation...")
            for ns1, ns2 in [
                (f"{vpc1}-public", f"{vpc2}-public"),
                (f"{vpc1}-private", f"{vpc2}-private"),
                (f"{vpc1}-public", f"{vpc2}-private"),
                (f"{vpc1}-private", f"{vpc2}-public")
            ]:
                target_ip = self._get_namespace_ip(ns2)
                if target_ip:
                    success, _ = self.check_connectivity(ns1, target_ip, verbose=False)
                    if success:
                        return False, f"Found connectivity between {ns1} and {ns2}"
            
            return True, None
        except Exception as e:
            return False, f"Isolation validation failed: {str(e)}"
            
    def validate_nat_behavior(self, namespace: str) -> Tuple[bool, Dict[str, Dict]]:
        """Validate NAT behavior for a namespace"""
        results = {
            "outbound_internet": {
                "success": False,
                "details": "",
                "tests": {}
            },
            "dns_resolution": {
                "success": False,
                "details": "",
                "tests": {}
            },
            "source_nat": {
                "success": False,
                "details": "",
                "tests": {}
            },
            "subnet_connectivity": {
                "success": False,
                "details": "",
                "tests": {}
            }
        }
        
        try:
            # 1. Test outbound internet access
            logger.info(f"Testing outbound internet access for {namespace}...")
            
            # Test TCP connectivity (port 80/443)
            cmd = ["curl", "-s", "-S", "-m", "5", "-o", "/dev/null", "http://example.com"]
            result = self.execute_command(cmd, namespace=namespace, check=False)
            results["outbound_internet"]["tests"]["http"] = result.returncode == 0
            
            # Test ICMP connectivity
            success, _ = self.check_connectivity(namespace, "8.8.8.8", verbose=False)
            results["outbound_internet"]["tests"]["icmp"] = success
            
            results["outbound_internet"]["success"] = any(results["outbound_internet"]["tests"].values())
            results["outbound_internet"]["details"] = f"HTTP: {'✓' if results['outbound_internet']['tests']['http'] else '✗'}, ICMP: {'✓' if results['outbound_internet']['tests']['icmp'] else '✗'}"
            
            # 2. Test DNS resolution
            logger.info(f"Testing DNS resolution for {namespace}...")
            
            # Test basic DNS resolution
            cmd = ["nslookup", "-timeout=5", "google.com"]
            result = self.execute_command(cmd, namespace=namespace, check=False)
            results["dns_resolution"]["tests"]["lookup"] = result.returncode == 0
            
            # Test DNS configuration
            cmd = ["cat", "/etc/netns/" + namespace + "/resolv.conf"]
            result = self.execute_command(cmd, check=False)
            has_nameserver = "nameserver" in result.stdout
            results["dns_resolution"]["tests"]["config"] = has_nameserver
            
            results["dns_resolution"]["success"] = all(results["dns_resolution"]["tests"].values())
            results["dns_resolution"]["details"] = f"Resolution: {'✓' if results['dns_resolution']['tests']['lookup'] else '✗'}, Config: {'✓' if results['dns_resolution']['tests']['config'] else '✗'}"
            
            # 3. Test source NAT
            logger.info(f"Testing source NAT for {namespace}...")
            
            # Get internal IP
            cmd = ["ip", "-j", "addr", "show"]
            result = self.execute_command(cmd, namespace=namespace)
            internal_ip = None
            addrs = json.loads(result.stdout)
            for iface in addrs:
                if iface["ifname"].startswith("veth"):
                    for addr in iface.get("addr_info", []):
                        if addr["family"] == "inet":
                            internal_ip = addr["local"]
                            break
            
            # Get external IP (as seen by internet)
            cmd = ["curl", "-s", "https://api.ipify.org"]
            result = self.execute_command(cmd, namespace=namespace, check=False)
            if result.returncode == 0:
                external_ip = result.stdout.strip()
                results["source_nat"]["tests"]["ip_masquerade"] = internal_ip != external_ip
                results["source_nat"]["details"] = f"Internal: {internal_ip}, External: {external_ip}"
            
            results["source_nat"]["success"] = results["source_nat"]["tests"].get("ip_masquerade", False)
            
            # 4. Test inter-subnet connectivity
            logger.info(f"Testing inter-subnet connectivity...")
            
            # Extract VPC name from namespace
            vpc_name = namespace.split('-')[0]
            other_ns = f"{vpc_name}-{'private' if 'public' in namespace else 'public'}"
            
            # Get other namespace's IP
            other_ip = None
            for route in self.check_namespace(other_ns)["routes"]:
                if "src" in route:
                    other_ip = route.split("src")[1].strip()
                    break
            
            if other_ip:
                success, _ = self.check_connectivity(namespace, other_ip, verbose=False)
                results["subnet_connectivity"]["tests"]["ping"] = success
                results["subnet_connectivity"]["details"] = f"Connectivity to {other_ns} ({other_ip}): {'✓' if success else '✗'}"
                results["subnet_connectivity"]["success"] = success
            
            # Print detailed results
            for category, result in results.items():
                logger.info(f"\n{category.replace('_', ' ').title()}:")
                logger.info(f"Success: {'✓' if result['success'] else '✗'}")
                logger.info(f"Details: {result['details']}")
                if result['tests']:
                    for test, passed in result['tests'].items():
                        logger.info(f"  - {test}: {'✓' if passed else '✗'}")
            
            return all(r["success"] for r in results.values()), results
            
        except Exception as e:
            logger.error(f"NAT validation failed: {e}")
            return False, results
    
    def _verify_network_setup(self, namespace: str) -> Tuple[bool, str]:
        """Verify network setup including routing and masquerading.
        
        Args:
            namespace (str): The namespace to verify
            
        Returns:
            Tuple[bool, str]: Success status and error message if any
        """
        try:
            logger.info(f"Verifying network setup for namespace {namespace}...")
            
            # Check interface is up and has address
            iface = None
            addr_cmd = ["ip", "addr", "show"]
            result = self.execute_command(addr_cmd, namespace=namespace)
            if result.returncode != 0:
                logger.error(f"Failed to get interface info: {result.stderr}")
                return False, f"Failed to get interface info: {result.stderr}"
                
            logger.info("Network interface status:")
            logger.info(result.stdout)
                
            for line in result.stdout.split("\n"):
                if "veth" in line and "state UP" in line:
                    iface = line.split(":")[1].strip()
                elif iface and "inet" in line:
                    break
            else:
                return False, "No active veth interface with IP address found"
                
            # Check routing
            logger.info("Checking routing configuration...")
            route_cmd = ["ip", "route", "show"]
            result = self.execute_command(route_cmd, namespace=namespace)
            if result.returncode != 0:
                logger.error(f"Failed to get routes: {result.stderr}")
                return False, f"Failed to get routes: {result.stderr}"
            
            logger.info("Routing table:")
            logger.info(result.stdout)
            
            has_default_route = False
            for line in result.stdout.split("\n"):
                if line.startswith("default"):
                    has_default_route = True
                    logger.info(f"Found default route: {line}")
                    break

            if not has_default_route:
                logger.warning("No default route found")
                return True, "No default route found"

            return True, ""
            
        except Exception as e:
            return False, f"Network setup verification failed: {str(e)}"

    def _fix_network_setup(self, namespace: str):
        """Attempt to fix network setup issues"""
        try:
            logger.info(f"Attempting to fix network setup for {namespace}...")
            
            # Find veth interface
            veth = None
            result = self.execute_command(["ip", "link"], namespace=namespace)
            logger.info("Available interfaces:")
            logger.info(result.stdout)
            
            for line in result.stdout.split("\n"):
                if "veth" in line:
                    veth = line.split(":")[1].strip()
                    logger.info(f"Found veth interface: {veth}")
                    break
            
            if veth:
                self.execute_command(["ip", "link", "set", veth, "up"], namespace=namespace)
                result = self.execute_command(["ip", "route", "show"], namespace=namespace)
                if "default" not in result.stdout:
                    logger.debug("Default route still missing after attempted fix")
            
        except Exception as e:
            logger.error(f"Failed to fix network setup: {str(e)}")

    def validate_security_rules(self, namespace: str, rules: List[Dict]) -> Tuple[bool, Dict[str, Dict]]:
        """Validate that security rules are properly enforced

        Args:
            namespace (str): The namespace to validate rules in
            rules (List[Dict]): List of security rules to validate. Each rule should have:
                - direction: "inbound" or "outbound"
                - protocol: "tcp", "udp", or "icmp"
                - port: port number (for TCP/UDP)
                - source: source CIDR (for inbound) or target CIDR (for outbound)
                - action: "allow" or "deny"

        Returns:
            Tuple[bool, Dict[str, Dict]]: Success status and detailed results
        """
        # Verify network setup first
        setup_ok, error = self._verify_network_setup(namespace)
        if not setup_ok:
            logger.error(f"Network setup verification failed: {error}")
            logger.info("Attempting to fix network setup...")
            self._fix_network_setup(namespace)
            setup_ok, error = self._verify_network_setup(namespace)
            if not setup_ok:
                logger.error(f"Could not fix network setup: {error}")
        results = {
            "inbound_rules": {
                "success": False,
                "details": "",
                "tests": {}
            },
            "outbound_rules": {
                "success": False,
                "details": "",
                "tests": {}
            },
            "default_deny": {
                "success": False,
                "details": "",
                "tests": {}
            }
        }
        
        try:
            logger.info(f"Starting security rule validation for {namespace}...")
            
            # 1. Test Default Deny Behavior
            logger.info("Testing default deny behavior...")
            
            # Test TCP to common ports
            for port in [22, 80, 443, 8080]:
                cmd = ["nc", "-z", "-w2", "127.0.0.1", str(port)]
                result = self.execute_command(cmd, namespace=namespace, check=False)
                results["default_deny"]["tests"][f"tcp_{port}"] = (result.returncode != 0)
            
            # Test UDP to common ports with improved UDP testing and logging
            logger.info("Testing UDP default deny behavior...")
            for port in [53, 123]:
                logger.info(f"Testing UDP port {port}...")
                is_accessible = self._test_udp_connectivity(
                    namespace, "127.0.0.1", port, direction="inbound"
                )
                results["default_deny"]["tests"][f"udp_{port}"] = not is_accessible
                logger.info(f"UDP port {port} {'is' if is_accessible else 'is not'} accessible")
            
            results["default_deny"]["success"] = all(results["default_deny"]["tests"].values())
            results["default_deny"]["details"] = (
                "Default deny behavior working as expected" if results["default_deny"]["success"]
                else f"Some ports accessible without rules: " + 
                     ", ".join(f"UDP/{port}" for port in [53, 123] 
                             if not results["default_deny"]["tests"][f"udp_{port}"])
            )
            
            # 2. Test Each Rule
            for rule in rules:
                direction = rule.get("direction", "inbound")
                protocol = rule.get("protocol", "tcp")
                port = rule.get("port", 80)
                source = rule.get("source", "0.0.0.0/0")
                action = rule.get("action", "allow")
                category = f"{direction}_rules"
                test_key = f"{protocol}_{port}_{source.replace('/', '_')}"
                
                logger.info(f"Testing {direction} {protocol} rule for port {port} from {source}...")
                
                if protocol.lower() in ["tcp", "udp"]:
                    # Get namespace IP for proper targeting
                    namespace_ip = self._get_namespace_ip(namespace)
                    logger.info(f"Namespace IP: {namespace_ip}")
                    
                    if direction == "inbound":
                        target_ip = namespace_ip
                        test_namespace = None  # Test from host (no namespace) to namespace
                    else:
                        target_ip = "8.8.8.8"
                        test_namespace = namespace  # Test from namespace to internet
                    
                    source_ip = None
                    # Handle source IP for inbound rules with CIDR
                    if "/" in source:
                        network = source.split("/")[0]  # Network address
                        netmask = int(source.split("/")[1])  # Network mask
                        if network == "0.0.0.0" and netmask == 0:
                            source_ip = "10.0.0.2" if direction == "inbound" else None
                        else:
                            # Use a valid IP from the specified network
                            ip_parts = network.split(".")
                            ip_parts[-1] = "2"  # Use .2 as host part to avoid gateway
                            source_ip = ".".join(ip_parts)
                        logger.info(f"Using source IP {source_ip} for CIDR {source}")
                    
                    # Use appropriate test method based on protocol with detailed logging
                    logger.info(f"\nTesting {direction} {protocol} connectivity:")
                    logger.info(f"  From: {test_namespace} (source IP: {source_ip})")
                    logger.info(f"  To: {target_ip}:{port}")
                    logger.info(f"  Rule source CIDR: {source}")
                    
                    if protocol.lower() == "tcp":
                        test_result = self._test_tcp_connectivity(
                            test_namespace, target_ip, port, source_ip,
                            direction=direction
                        )
                        logger.info(f"  TCP test result: {'✓ Success' if test_result else '✗ Failed'}")
                    else:  # UDP
                        test_result = self._test_udp_connectivity(
                            test_namespace, target_ip, port,
                            direction=direction
                        )
                        logger.info(f"  UDP test result: {'✓ Success' if test_result else '✗ Failed'}")
                    
                    expected = (action.lower() == "allow")
                    results[category]["tests"][test_key] = (test_result == expected)
                    
                elif protocol.lower() == "icmp":
                    # For ICMP, test with ping
                    target = "8.8.8.8" if direction == "outbound" else self._get_namespace_ip(namespace)
                    success, _ = self.check_connectivity(namespace, target, verbose=False) if direction == "outbound" else \
                               self.check_connectivity("host", target, verbose=False)
                    
                    results[category]["tests"][test_key] = (success == (action.lower() == "allow"))
            
            # Calculate success for each category
            for category in ["inbound_rules", "outbound_rules"]:
                if results[category]["tests"]:
                    results[category]["success"] = all(results[category]["tests"].values())
                    results[category]["details"] = (
                        "All rules enforced correctly" if results[category]["success"]
                        else "Some rules not enforced correctly"
                    )
                else:
                    results[category]["success"] = True
                    results[category]["details"] = "No rules to test"
            
            # Calculate final results and format output
            all_passed = True
            summary = []
            
            for category, result in results.items():
                cat_name = category.replace('_', ' ').title()
                success = result['success']
                all_passed &= success
                
                summary.append(f"\n=== {cat_name} ===")
                summary.append(f"Status: {'✓ Passed' if success else '✗ Failed'}")
                summary.append(f"Details: {result['details']}")
                
                if result['tests']:
                    summary.append("Individual Tests:")
                    for test, passed in result['tests'].items():
                        test_name = test.replace('_', ' ').title()
                        summary.append(f"  - {test_name}: {'✓' if passed else '✗'}")
                        if not passed:
                            rule_info = next((r for r in rules if 
                                f"{r.get('protocol', 'tcp')}_{r.get('port', '')}_{r.get('source', '').replace('/', '_')}" == test), None)
                            if rule_info:
                                summary.append(f"    Rule: {json.dumps(rule_info, indent=2)}")
                
                summary.append("")  # Empty line between categories
            
            # Print formatted results
            logger.info("\n=== Security Rules Validation Report ===")
            logger.info(f"Namespace: {namespace}")
            logger.info(f"Overall Status: {'✓ Passed' if all_passed else '✗ Failed'}")
            logger.info("\nDetailed Results:")
            for line in summary:
                logger.info(line)
            logger.info("\n=== End Report ===")
            
            return all_passed, results
            
        except Exception as e:
            error_msg = f"Security rule validation failed: {str(e)}"
            logger.error(f"\n=== Security Rules Validation Error ===")
            logger.error(f"Namespace: {namespace}")
            logger.error(f"Error: {error_msg}")
            logger.error("\nPartial Results:")
            for category, result in results.items():
                if result['tests']:
                    logger.error(f"\n{category.replace('_', ' ').title()}:")
                    for test, passed in result['tests'].items():
                        logger.error(f"  - {test}: {'✓' if passed else '✗'}")
            logger.error("\n=== End Error Report ===")
            return False, results
            
    def _get_namespace_ip(self, namespace: str) -> Optional[str]:
        """Get the first IPv4 address of a namespace's interface"""
        try:
            cmd = ["ip", "-j", "addr", "show"]
            result = self.execute_command(cmd, namespace=namespace)
            addrs = json.loads(result.stdout)
            
            for iface in addrs:
                # Look for veth interfaces (skip loopback)
                if iface["ifname"] != "lo":
                    for addr in iface.get("addr_info", []):
                        if addr["family"] == "inet":
                            return addr["local"]
            return None
        except Exception as e:
            logger.debug(f"Failed to get namespace IP for {namespace}: {e}")
            return None

    def _test_udp_connectivity(self, namespace: str, target: str, port: int, 
                             timeout: int = 2, direction: str = "outbound") -> bool:
        """Test UDP connectivity by sending and receiving data.
        
        Args:
            namespace: The namespace to test from/to
            target: Target IP address
            port: UDP port to test
            timeout: Timeout in seconds
            direction: 'inbound' or 'outbound' to determine test direction
            
        Returns:
            bool: True if connection successful, False otherwise
        """
        try:
            server_output = None
            client_output = None
            success = False
            
            if direction == "inbound":
                # For inbound tests, start listener in namespace
                logger.debug(f"Starting UDP listener in namespace {namespace} on port {port}")
                server_cmd = ["ip", "netns", "exec", namespace, "nc", "-u", "-l", "-p", str(port)]
            else:
                # For outbound tests, start listener on host
                logger.debug(f"Starting UDP listener on host on port {port}")
                server_cmd = ["nc", "-u", "-l", "-p", str(port)]

            # Start UDP server with timeout
            with subprocess.Popen(server_cmd, 
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE) as server:
                # Give server time to start
                time.sleep(0.5)
                
                # Prepare client command
                test_data = b"UDP test packet\n"
                if direction == "inbound":
                    # Send from host to namespace
                    logger.debug(f"Sending UDP packet to {target}:{port}")
                    client_cmd = ["nc", "-u", "-w1", target, str(port)]
                    client_proc = subprocess.run(client_cmd, 
                                              input=test_data,
                                              stdout=subprocess.PIPE, 
                                              stderr=subprocess.PIPE)
                else:
                    # Send from namespace to host
                    logger.debug(f"Sending UDP packet from namespace to {target}:{port}")
                    client_cmd = ["bash", "-c", f"echo 'UDP test packet' | nc -u -w1 {target} {port}"]
                    client_proc = self.execute_command(client_cmd, namespace=namespace, check=False)
                
                # Wait briefly for packet to be received
                time.sleep(0.5)
                
                # Get output
                server.terminate()
                try:
                    server_output = server.communicate(timeout=1)[0]
                    server.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server_output = b""
                
                client_output = client_proc.stderr

                # Check if data was received
                success = (server_output == test_data if direction == "inbound" 
                         else client_proc.returncode == 0)
                
                logger.debug(f"UDP Test Results for {direction} on port {port}:")
                logger.debug(f"Server output: {server_output}")
                logger.debug(f"Client stderr: {client_output}")
                logger.debug(f"Success: {success}")
            
            return success
            
        except Exception as e:
            logger.error(f"UDP test failed: {str(e)}")
            return False

    def create_vpc_peering(self, vpc1: str, vpc2: str) -> Tuple[bool, Optional[str]]:
        """Create a VPC peering connection between two VPCs.
        
        Args:
            vpc1 (str): Name of the first VPC
            vpc2 (str): Name of the second VPC
            
        Returns:
            Tuple[bool, Optional[str]]: Success status and error message if any
        """
        try:
            logger.info(f"Creating VPC peering between {vpc1} and {vpc2}...")
            
            # Validate both VPCs exist and are properly configured
            vpc1_valid = self.validate_vpc(vpc1, "")
            vpc2_valid = self.validate_vpc(vpc2, "")
            
            if vpc1_valid["status"] != "success":
                return False, f"VPC {vpc1} validation failed: {vpc1_valid['errors']}"
            if vpc2_valid["status"] != "success":
                return False, f"VPC {vpc2} validation failed: {vpc2_valid['errors']}"
            
            # Get VPC CIDRs and bridge information
            vpc1_cidr = self._get_vpc_cidr(vpc1)
            vpc2_cidr = self._get_vpc_cidr(vpc2)
            vpc1_bridge = f"br-{vpc1}"
            vpc2_bridge = f"br-{vpc2}"
            if not self.check_bridge(vpc1_bridge)["exists"]:
                vpc1_bridge = f"{vpc1}-bridge"
            if not self.check_bridge(vpc2_bridge)["exists"]:
                vpc2_bridge = f"{vpc2}-bridge"
            
            if not vpc1_cidr or not vpc2_cidr:
                return False, "Could not determine VPC CIDRs"
            
            logger.info(f"VPC1 CIDR: {vpc1_cidr}")
            logger.info(f"VPC2 CIDR: {vpc2_cidr}")
            
            # Create veth pair for peering
            peer1 = f"{vpc1}-to-{vpc2}"
            peer2 = f"{vpc2}-to-{vpc1}"
            
            # Create veth pair
            try:
                self.execute_command(["ip", "link", "add", peer1, "type", "veth", "peer", "name", peer2])
                logger.info(f"Created veth pair: {peer1} <-> {peer2}")
            except Exception as e:
                return False, f"Failed to create veth pair: {str(e)}"
            
            # Connect each end to respective bridge
            try:
                self.execute_command(["ip", "link", "set", peer1, "master", vpc1_bridge])
                self.execute_command(["ip", "link", "set", peer2, "master", vpc2_bridge])
                self.execute_command(["ip", "link", "set", peer1, "up"])
                self.execute_command(["ip", "link", "set", peer2, "up"])
                logger.info("Connected veth pairs to bridges")
            except Exception as e:
                # Cleanup on failure
                self.execute_command(["ip", "link", "del", peer1], check=False)
                return False, f"Failed to connect veth pairs: {str(e)}"
            
            # Update routing in VPC namespaces for cross-VPC communication
            # For each namespace, add route to peer VPC network through the peer's bridge
            for vpc, peer_vpc, peer_cidr in [(vpc1, vpc2, vpc2_cidr), (vpc2, vpc1, vpc1_cidr)]:
                for subnet_type in ["public", "private"]:
                    ns_name = f"{vpc}-{subnet_type}"
                    try:
                        # Route to peer VPC through local bridge
                        # The bridges are connected via peering veth pair
                        peer_bridge = f"br-{peer_vpc}"
                        if not self.check_bridge(peer_bridge)["exists"]:
                            peer_bridge = f"{peer_vpc}-bridge"
                        
                        # Get the bridge IP from the host side
                        result = self.execute_command(["ip", "addr", "show", "dev", peer_bridge], check=False)
                        if result.returncode == 0 and "inet" in result.stdout:
                            # Extract bridge IP
                            for line in result.stdout.split('\n'):
                                if 'inet ' in line:
                                    bridge_ip = line.strip().split()[1].split('/')[0]
                                    break
                        else:
                            # Fallback: use calculated gateway IP from peer VPC CIDR
                            peer_network = ipaddress.ip_network(peer_cidr)
                            bridge_ip = str(peer_network.network_address + 1)
                        
                        # Add route to peer network via their bridge
                        self.execute_command([
                            "ip", "route", "add", peer_cidr, "via", bridge_ip
                        ], namespace=ns_name, check=False)
                        logger.info(f"Added route in {ns_name} to {peer_cidr} via {bridge_ip}")
                        
                    except Exception as e:
                        logger.warning(f"Route addition warning in {ns_name}: {str(e)}")
            
            return True, None
            
        except Exception as e:
            logger.error(f"VPC peering creation failed: {str(e)}")
            return False, str(e)
    
    def delete_vpc_peering(self, vpc1: str, vpc2: str) -> Tuple[bool, Optional[str]]:
        """Delete a VPC peering connection between two VPCs.
        
        Args:
            vpc1 (str): Name of the first VPC
            vpc2 (str): Name of the second VPC
            
        Returns:
            Tuple[bool, Optional[str]]: Success status and error message if any
        """
        try:
            logger.info(f"Deleting VPC peering between {vpc1} and {vpc2}...")
            
            # Remove routes in VPC namespaces
            vpc1_cidr = self._get_vpc_cidr(vpc1)
            vpc2_cidr = self._get_vpc_cidr(vpc2)
            
            if vpc1_cidr and vpc2_cidr:
                for ns1, ns2, cidr in [(f"{vpc1}-public", f"{vpc2}-public", vpc2_cidr),
                                     (f"{vpc1}-private", f"{vpc2}-private", vpc2_cidr),
                                     (f"{vpc2}-public", f"{vpc1}-public", vpc1_cidr),
                                     (f"{vpc2}-private", f"{vpc1}-private", vpc1_cidr)]:
                    try:
                        self.execute_command(
                            ["ip", "route", "del", cidr],
                            namespace=ns1,
                            check=False
                        )
                        logger.info(f"Removed route in {ns1} to {cidr}")
                    except Exception as e:
                        logger.warning(f"Route deletion warning in {ns1}: {str(e)}")
            
            # Remove veth pair
            peer1 = f"{vpc1}-to-{vpc2}"
            try:
                self.execute_command(["ip", "link", "del", peer1], check=False)
                logger.info(f"Removed veth pair {peer1}")
            except Exception as e:
                logger.warning(f"Veth pair deletion warning: {str(e)}")
            
            return True, None
            
        except Exception as e:
            logger.error(f"VPC peering deletion failed: {str(e)}")
            return False, str(e)
    
    def _get_vpc_cidr(self, vpc: str) -> Optional[str]:
        """Get CIDR block for a VPC.
        
        Args:
            vpc (str): Name of the VPC
            
        Returns:
            Optional[str]: CIDR block if found, None otherwise
        """
        try:
            # First check if we have it stored
            if vpc in self._vpc_cidrs:
                return self._vpc_cidrs[vpc]
                
            # Fallback: try to determine from namespace IP
            ns_ip = self._get_namespace_ip(f"{vpc}-public")
            if ns_ip:
                # Convert IP to CIDR by assuming /24 subnet
                cidr_parts = ns_ip.split('.')
                cidr_parts[-1] = "0/24"  # Replace last octet with 0/24
                cidr = ".".join(cidr_parts)
                # Store it for future use
                self._vpc_cidrs[vpc] = cidr
                return cidr
            return None
        except:
            return None
    
    def create_vpc(self, name: str, cidr: str) -> Tuple[bool, Optional[str]]:
        """Create a new VPC with the specified name and CIDR block.
        
        Args:
            name (str): Name of the VPC
            cidr (str): CIDR block for the VPC (e.g., '10.0.0.0/16')
            
        Returns:
            Tuple[bool, Optional[str]]: Success status and error message if any
        """
        try:
            logger.info(f"Creating VPC {name} with CIDR {cidr}")
            
            # Validate CIDR format
            try:
                network = ipaddress.ip_network(cidr)
                if network.prefixlen < 16 or network.prefixlen > 28:
                    return False, "CIDR prefix length must be between /16 and /28"
            except ValueError as e:
                return False, f"Invalid CIDR format: {str(e)}"
                
            # Check if VPC already exists
            bridge_name = f"{name}-bridge"
            result = self.execute_command(["ip", "link", "show", bridge_name], check=False)
            if result.returncode == 0:
                logger.info(f"VPC {name} already exists, cleaning up first...")
                success, error = self.delete_vpc(name)
                if not success:
                    return False, f"Failed to cleanup existing VPC: {error}"
                
            # Create public and private subnets
            public_cidr = list(network.subnets(new_prefix=network.prefixlen + 1))[0]
            private_cidr = list(network.subnets(new_prefix=network.prefixlen + 1))[1]
            
            # Create bridge for VPC
            self.execute_command(["ip", "link", "add", "name", bridge_name, "type", "bridge"])
            self.execute_command(["ip", "link", "set", bridge_name, "up"])
            logger.info(f"Created bridge {bridge_name}")
            
            # Create public and private namespaces
            for subnet_type, subnet_cidr in [("public", public_cidr), ("private", private_cidr)]:
                ns_name = f"{name}-{subnet_type}"
                
                # Create namespace
                self.execute_command(["ip", "netns", "add", ns_name])
                logger.info(f"Created namespace {ns_name}")
                
                # Create veth pair with shorter names (Linux interface names max 15 chars)
                veth_suffix = "pub" if subnet_type == "public" else "prv"
                veth1 = f"{name}-{veth_suffix}1"  # e.g., vpc1-pub1
                veth2 = f"{name}-{veth_suffix}2"  # e.g., vpc1-pub2
                self.execute_command(["ip", "link", "add", veth1, "type", "veth", "peer", "name", veth2])
                
                # Move one end to namespace
                self.execute_command(["ip", "link", "set", veth2, "netns", ns_name])
                
                # Connect other end to bridge
                self.execute_command(["ip", "link", "set", veth1, "master", bridge_name])
                self.execute_command(["ip", "link", "set", veth1, "up"])
                
                # Configure interface in namespace
                ns_ip = str(subnet_cidr.network_address + 1)  # First IP in subnet
                self.execute_command(["ip", "addr", "add", f"{ns_ip}/{subnet_cidr.prefixlen}", "dev", veth2], namespace=ns_name)
                self.execute_command(["ip", "link", "set", veth2, "up"], namespace=ns_name)
                self.execute_command(["ip", "link", "set", "lo", "up"], namespace=ns_name)
                
                logger.info(f"Configured {subnet_type} subnet {subnet_cidr} in {ns_name} with IP {ns_ip}")
                
            # Store VPC configuration
            self._vpc_cidrs[name] = str(network)
            logger.info(f"VPC {name} created successfully")
            
            return True, None
            
        except Exception as e:
            error_msg = f"Failed to create VPC: {str(e)}"
            logger.error(error_msg)
            return False, error_msg

    def delete_vpc(self, name: str) -> Tuple[bool, Optional[str]]:
        """Delete a VPC and all its associated resources.
        
        Args:
            name (str): Name of the VPC to delete
            
        Returns:
            Tuple[bool, Optional[str]]: Success status and error message if any
        """
        try:
            logger.info(f"Deleting VPC {name}...")
            
            # Delete namespaces
            for subnet_type in ["public", "private"]:
                ns_name = f"{name}-{subnet_type}"
                result = self.execute_command(["ip", "netns", "list"], check=False)
                if ns_name in result.stdout:
                    self.execute_command(["ip", "netns", "del", ns_name], check=False)
                    logger.info(f"Deleted namespace {ns_name}")
            
            # Delete bridge
            bridge_name = f"{name}-bridge"
            result = self.execute_command(["ip", "link", "show", bridge_name], check=False)
            if result.returncode == 0:
                self.execute_command(["ip", "link", "del", bridge_name], check=False)
                logger.info(f"Deleted bridge {bridge_name}")
            
            # Remove from VPC tracking
            if name in self._vpc_cidrs:
                del self._vpc_cidrs[name]
            
            return True, None
            
        except Exception as e:
            error_msg = f"Failed to delete VPC: {str(e)}"
            logger.error(error_msg)
            return False, error_msg

    def _test_tcp_connectivity(self, namespace: str, target: str, port: int, 
                             source_ip: Optional[str] = None, timeout: int = 2,
                             direction: str = "outbound") -> bool:
        """Test TCP connectivity with proper source IP handling and direction support.
        
        Args:
            namespace: The namespace to test from/to
            target: Target IP address
            port: TCP port to test
            source_ip: Optional source IP to use
            timeout: Connection timeout in seconds
            direction: 'inbound' or 'outbound' (default) to determine test direction
            
        Returns:
            bool: True if connection successful, False otherwise
        """
        try:
            logger.info(f"\nTCP Test Details:")
            logger.info(f"Direction: {direction}")
            logger.info(f"Target: {target}:{port}")
            logger.info(f"Namespace: {namespace}")
            logger.info(f"Source IP: {source_ip if source_ip else 'default'}")

            # For outbound tests to port 53, try real DNS servers
            if direction == "outbound" and port == 53:
                logger.info("Testing outbound DNS (TCP/53) connectivity...")
                dns_servers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
                for dns in dns_servers:
                    logger.info(f"Attempting TCP connection to DNS server {dns}:53")
                    # Add source IP if specified to prevent routing issues
                    cmd = ["nc", "-zvw2"]
                    if source_ip:
                        cmd.extend(["-s", source_ip])
                    cmd.extend([dns, "53"])
                    
                    result = self.execute_command(cmd, namespace=namespace, check=False)
                    logger.info(f"Connection result: {result.returncode}")
                    logger.info(f"Output: {result.stdout}")
                    logger.info(f"Error: {result.stderr}")
                    if result.returncode == 0:
                        logger.info(f"Successfully connected to DNS {dns}:53")
                        return True
                logger.info("Failed to connect to any DNS servers")
                return False
            
            if direction == "inbound":
                # For inbound tests, quickly test if port is accessible
                logger.info(f"Testing inbound TCP connection to port {port}")
                
                # Start a quick listener in the namespace
                if namespace:
                    listener_cmd = ["ip", "netns", "exec", namespace, "nc", "-l", "-p", str(port)]
                else:
                    listener_cmd = ["nc", "-l", "-p", str(port)]
                
                with subprocess.Popen(
                    listener_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                ) as listener:
                    # Give listener a moment to start
                    time.sleep(0.2)
                    # Give listener time to start
                    time.sleep(0.5)
                    
                    # Get target IP (namespace IP for inbound tests)
                    ns_ip = self._get_namespace_ip(namespace if namespace else target)
                    if not ns_ip:
                        logger.error("Could not get target namespace IP")
                        return False
                    
                    # For inbound tests, use source IP from the allowed CIDR
                    if not source_ip:
                        # Create a temporary interface in the correct subnet for testing
                        temp_iface = f"test_{int(time.time())}"
                        try:
                            subprocess.run(["ip", "link", "add", "dev", temp_iface, "type", "dummy"], check=True)
                            subprocess.run(["ip", "addr", "add", "10.0.0.3/24", "dev", temp_iface], check=True)
                            subprocess.run(["ip", "link", "set", temp_iface, "up"], check=True)
                            source_ip = "10.0.0.3"
                            logger.info(f"Created temporary interface {temp_iface} with IP {source_ip}")
                        except Exception as e:
                            logger.error(f"Failed to create temporary interface: {e}")
                            return False
                    
                    # Quick connection test with timeout
                    client_cmd = ["nc", "-z", "-v", "-w1"]  # Zero-I/O mode with 1s timeout
                    if source_ip:
                        client_cmd.extend(["-s", source_ip])
                    client_cmd.extend([ns_ip, str(port)])
                    
                    logger.info(f"Testing connection: {' '.join(client_cmd)}")
                    result = subprocess.run(
                        client_cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    
                    # Clean up temporary interface if we created one
                    if source_ip == "10.0.0.3":
                        try:
                            subprocess.run(["ip", "link", "del", temp_iface], check=False)
                            logger.info(f"Cleaned up temporary interface {temp_iface}")
                        except Exception as e:
                            logger.debug(f"Cleanup error (non-critical): {e}")
                    
                    # Clean up listener
                    listener.terminate()
                    try:
                        listener.wait(timeout=0.2)
                    except subprocess.TimeoutExpired:
                        listener.kill()
                    
                    success = result.returncode == 0
                    logger.info(f"Test result: {'✓ Success' if success else '✗ Failed'}")
                    if not success:
                        logger.debug(f"Connection error: {result.stderr}")
                    
                    return success
                    
            else:
                # For outbound tests, try to establish connection
                cmd = ["nc", "-zv", "-w", str(timeout)]
                if source_ip:
                    cmd.extend(["-s", source_ip])
                cmd.extend([target, str(port)])
                
                logger.info(f"Attempting outbound connection with command: {' '.join(cmd)}")
                result = self.execute_command(cmd, namespace=namespace, check=False)
                
                # Log detailed results
                logger.info("\nTest Results:")
                logger.info(f"Command output: {result.stdout}")
                logger.info(f"Command error: {result.stderr}")
                logger.info(f"Return code: {result.returncode}")
                
                success = result.returncode == 0
                logger.info(f"Test result: {'✓ Success' if success else '✗ Failed'}")
                return success
                
        except Exception as e:
            logger.error(f"TCP test failed with exception: {str(e)}")
            import traceback
            logger.error(f"Stack trace:\n{traceback.format_exc()}")
            return False