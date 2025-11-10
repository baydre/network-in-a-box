#!/usr/bin/env python3

import argparse
import hashlib
import ipaddress
import json
import logging
import os
import subprocess
import sys
from typing import Dict, List, Optional, Tuple

from exceptions import (
    NetworkInABoxError, ValidationError, ResourceExistsError,
    ResourceNotFoundError, NetworkConfigError, StateError
)
from validation import (
    validate_vpc_name, validate_cidr, validate_ip_address,
    validate_port, validate_protocol, validate_interface_name,
    validate_security_rule, check_vpc_conflicts, check_cidr_overlap
)
from state import StateManager
from monitor import NetworkMonitor
from network_validator import NetworkValidator
from policy import PolicyManager
from test_servers import TestServer

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class NetworkInABox:
    def __init__(self):
        # Verify running as root
        if os.geteuid() != 0:
            logger.error("This script must be run as root!")
            sys.exit(1)
            
        # Initialize default paths
        self.state_dir = "/var/tmp"
        self.state_file = os.path.join(self.state_dir, "network_in_a_box.state")
        
        # Initialize components
        self.monitor = NetworkMonitor()
        self.validator = NetworkValidator()
        self.state_manager = StateManager(self.state_file)
        self.policy_manager = PolicyManager(os.path.join(os.path.dirname(__file__), "..", "policies"))
        self.test_server = TestServer()
        
        # Load initial state
        try:
            self.vpcs = self.state_manager.get_all_vpcs()
            logger.debug(f"Loaded VPCs from state: {self.vpcs}")
        except Exception as e:
            logger.error(f"Failed to load initial state: {e}")
            self.vpcs = {}
    
    def _load_state(self):
        """Load VPC state from file"""
        try:
            with open(self.state_file, 'r') as f:
                return json.loads(f.read())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}
    
    def _save_state(self):
        """Save VPC state to file"""
        with open(self.state_file, 'w') as f:
            json.dump(self.vpcs, f)
    
    def execute_command(self, command, check=True):
        """Execute a shell command and log it"""
        logger.debug(f"Executing: {' '.join(command)}")
        try:
            result = subprocess.run(command, check=check, capture_output=True, text=True)
            return result
        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed: {e.cmd}")
            logger.error(f"Error output: {e.stderr}")
            if check:
                raise
            return e
    
    def create_namespace(self, name: str, dns_servers: Optional[List[str]] = None):
        """Create a network namespace with optional DNS configuration."""
        logger.info(f"Creating network namespace: {name}")

        result = self.execute_command(["ip", "netns", "list"], check=False)
        if name in result.stdout:
            logger.info(f"Namespace {name} already exists")
            return

        self.execute_command(["ip", "netns", "add", name])
        self.execute_command(["ip", "netns", "exec", name, "ip", "link", "set", "lo", "up"])

        if dns_servers:
            netns_dir = f"/etc/netns/{name}"
            self.execute_command(["mkdir", "-p", netns_dir])
            resolv_conf = os.path.join(netns_dir, "resolv.conf")
            with open(resolv_conf, "w", encoding="ascii") as f:
                for server in dns_servers:
                    f.write(f"nameserver {server}\n")
            os.chmod(resolv_conf, 0o644)
    
    def create_bridge(self, name: str, ip_addrs: Optional[List[str]] = None):
        """Create a Linux bridge and optionally assign IP addresses."""
        import time
        logger.info(f"Creating bridge: {name}")

        # Load required kernel modules first
        self.execute_command(["modprobe", "bridge"], check=False)
        self.execute_command(["modprobe", "br_netfilter"], check=False)

        # Enable global network settings
        self.execute_command(["sysctl", "-w", "net.ipv4.ip_forward=1"])
        self.execute_command(["sysctl", "-w", "net.ipv4.conf.all.forwarding=1"])

        # Clean up any existing bridge with the same name
        self.execute_command(["ip", "link", "set", name, "down"], check=False)
        self.execute_command(["ip", "link", "del", name], check=False)

        # Create new bridge
        result = self.execute_command(["ip", "link", "add", name, "type", "bridge"])
        if result.returncode != 0:
            logger.error(f"Failed to create bridge {name}: {result.stderr}")
            raise NetworkConfigError(f"Bridge creation failed: {result.stderr}")

        # Bring up the bridge
        self.execute_command(["ip", "link", "set", "dev", name, "up"])
        time.sleep(0.5)

        # Configure networking parameters
        self.execute_command(["sysctl", "-w", f"net.ipv4.conf.{name}.forwarding=1"])
        self.execute_command(["sysctl", "-w", "net.ipv4.conf.all.proxy_arp=1"])
        self.execute_command(["sysctl", "-w", f"net.ipv4.conf.{name}.proxy_arp=1"])
        self.execute_command(["sysctl", "-w", "net.ipv4.conf.all.rp_filter=0"])
        self.execute_command(["sysctl", "-w", f"net.ipv4.conf.{name}.rp_filter=0"])

        # Assign IP addresses if provided
        self.execute_command(["ip", "addr", "flush", "dev", name])
        if ip_addrs:
            for addr in ip_addrs:
                self.execute_command(["ip", "addr", "add", addr, "dev", name])

        # Enable bridge-specific settings
        self.execute_command(["sysctl", "-w", "net.bridge.bridge-nf-call-iptables=1"])
        self.execute_command(["sysctl", "-w", "net.bridge.bridge-nf-call-ip6tables=1"])

        # Enable promiscuous mode for better network visibility
        self.execute_command(["ip", "link", "set", "dev", name, "promisc", "on"], check=False)

        bridge_info = self.validator.check_bridge(name)
        if not bridge_info['exists']:
            raise NetworkConfigError(f"Failed to create bridge {name}")

        logger.info(f"Bridge {name} configured successfully")
    
    def create_veth_pair(self, veth1, veth2):
        """Create a virtual ethernet pair"""
        logger.info(f"Creating veth pair: {veth1} <-> {veth2}")
        
        # Clean up any existing interfaces with same names
        for iface in [veth1, veth2]:
            result = self.execute_command(["ip", "link", "show", iface], check=False)
            if result.returncode == 0:
                logger.warning(f"Interface {iface} already exists, removing it")
                self.execute_command(["ip", "link", "del", iface], check=False)
        
        # Create the veth pair
        self.execute_command([
            "ip", "link", "add", veth1,
            "type", "veth",
            "peer", "name", veth2
        ])
    
    def setup_veth_in_namespace(
        self,
        veth_name: str,
        namespace: str,
        ip_addr: str,
        routes: Optional[List[Dict[str, str]]] = None,
        default_gateway: Optional[str] = None,
    ):
        """Move one end of a veth pair into a namespace and configure networking."""
        logger.info(f"Setting up {veth_name} in namespace {namespace} with IP {ip_addr}")

        try:
            self.execute_command(["ip", "link", "set", veth_name, "netns", namespace])
            self.execute_command([
                "ip", "netns", "exec", namespace,
                "ip", "addr", "add", ip_addr, "dev", veth_name
            ])
            self.execute_command([
                "ip", "netns", "exec", namespace,
                "ip", "link", "set", veth_name, "up"
            ])

            if routes:
                for route in routes:
                    dest = route.get("dest")
                    via = route.get("via")
                    if dest and via:
                        self.execute_command([
                            "ip", "netns", "exec", namespace,
                            "ip", "route", "replace", dest, "via", via
                        ], check=False)

            if default_gateway:
                self.execute_command([
                    "ip", "netns", "exec", namespace,
                    "ip", "route", "replace", "default", "via", default_gateway
                ], check=False)

            iface_info = self.validator.check_interface(veth_name, namespace)
            if not iface_info['exists'] or iface_info['state'] != 'UP':
                raise NetworkConfigError(
                    f"Failed to configure interface {veth_name} in namespace {namespace}"
                )

            logger.info(f"Interface {veth_name} configured successfully in namespace {namespace}")

        except Exception as exc:
            logger.error(f"Failed to set up interface {veth_name} in namespace {namespace}: {exc}")
            raise NetworkConfigError(f"Interface setup failed: {exc}")
    
    def connect_veth_to_bridge(self, veth_name, bridge_name):
        """Connect one end of veth pair to the bridge"""
        logger.info(f"Connecting {veth_name} to bridge {bridge_name}")
        self.execute_command(["ip", "link", "set", veth_name, "master", bridge_name])
        self.execute_command(["ip", "link", "set", veth_name, "up"])

    def _interface_tag(self, name: str) -> str:
        """Generate a unique short tag for interface naming."""
        import hashlib
        # Use hash to ensure uniqueness even with similar names
        hash_hex = hashlib.md5(name.encode()).hexdigest()[:4]
        # Keep first few chars of original name + hash
        clean_name = ''.join(ch for ch in name if ch.isalnum()).lower()[:4]
        return f"{clean_name}{hash_hex}"

    def _allocate_link_subnet(self, name: str) -> ipaddress.IPv4Network:
        base = ipaddress.ip_network("100.64.0.0/16")
        total_subnets = base.num_addresses // 4  # /30 networks
        index = int(hashlib.sha1(name.encode("ascii", "ignore")).hexdigest(), 16) % total_subnets
        network_address = int(base.network_address) + index * 4
        return ipaddress.ip_network((network_address, 30))

    def _configure_nat_internal_interface(self, namespace: str, iface: str, addresses: List[str]):
        self.execute_command(["ip", "link", "set", iface, "netns", namespace])
        for addr in addresses:
            self.execute_command([
                "ip", "netns", "exec", namespace,
                "ip", "addr", "add", addr, "dev", iface
            ])
        self.execute_command([
            "ip", "netns", "exec", namespace,
            "ip", "link", "set", iface, "up"
        ])

    def _configure_nat_external_interface(self, namespace: str, iface: str, address: str, gateway: str):
        self.execute_command(["ip", "link", "set", iface, "netns", namespace])
        self.execute_command([
            "ip", "netns", "exec", namespace,
            "ip", "addr", "add", address, "dev", iface
        ])
        self.execute_command([
            "ip", "netns", "exec", namespace,
            "ip", "link", "set", iface, "up"
        ])
        self.execute_command([
            "ip", "netns", "exec", namespace,
            "ip", "route", "replace", "default", "via", gateway
        ])

    def _configure_nat_firewall(
        self,
        namespace: str,
        internal_iface: str,
        external_iface: str,
        vpc_networks: List[str]
    ):
        cmds = [
            ["ip", "netns", "exec", namespace, "iptables", "-t", "nat", "-F"],
            ["ip", "netns", "exec", namespace, "iptables", "-F"],
            ["ip", "netns", "exec", namespace, "iptables", "-P", "FORWARD", "DROP"],
            ["ip", "netns", "exec", namespace, "iptables", "-A", "FORWARD", "-i", internal_iface, "-o", internal_iface, "-j", "ACCEPT"],
            ["ip", "netns", "exec", namespace, "iptables", "-A", "FORWARD", "-i", internal_iface, "-o", external_iface, "-j", "ACCEPT"],
            ["ip", "netns", "exec", namespace, "iptables", "-A", "FORWARD", "-i", external_iface, "-o", internal_iface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
            ["ip", "netns", "exec", namespace, "iptables", "-t", "nat", "-A", "POSTROUTING", "-o", external_iface, "-j", "MASQUERADE"],
        ]
        for cmd in cmds:
            self.execute_command(cmd, check=False)

        for cidr in vpc_networks:
            self.execute_command([
                "ip", "netns", "exec", namespace,
                "iptables", "-A", "INPUT",
                "-s", cidr,
                "-i", internal_iface,
                "-j", "ACCEPT"
            ], check=False)

    def _configure_host_firewall(
        self,
        host_iface: str,
        uplink_iface: str,
        link_subnet: ipaddress.IPv4Network
    ):
        self.execute_command(["sysctl", "-w", f"net.ipv4.conf.{host_iface}.forwarding=1"])
        self.execute_command(["sysctl", "-w", f"net.ipv4.conf.{host_iface}.rp_filter=0"])

        rules = [
            ["iptables", "-C", "FORWARD", "-i", host_iface, "-o", uplink_iface, "-j", "ACCEPT"],
            ["iptables", "-C", "FORWARD", "-i", uplink_iface, "-o", host_iface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
            ["iptables", "-t", "nat", "-C", "POSTROUTING", "-s", str(link_subnet), "-o", uplink_iface, "-j", "MASQUERADE"],
        ]

        add_commands = [
            ["iptables", "-A", "FORWARD", "-i", host_iface, "-o", uplink_iface, "-j", "ACCEPT"],
            ["iptables", "-A", "FORWARD", "-i", uplink_iface, "-o", host_iface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
            ["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", str(link_subnet), "-o", uplink_iface, "-j", "MASQUERADE"],
        ]

        for idx, check_cmd in enumerate(rules):
            result = self.execute_command(check_cmd, check=False)
            if result.returncode != 0:
                self.execute_command(add_commands[idx])

    def _remove_host_firewall(self, host_iface: str, uplink_iface: str, link_subnet: ipaddress.IPv4Network):
        removal_cmds = [
            ["iptables", "-D", "FORWARD", "-i", host_iface, "-o", uplink_iface, "-j", "ACCEPT"],
            ["iptables", "-D", "FORWARD", "-i", uplink_iface, "-o", host_iface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
            ["iptables", "-t", "nat", "-D", "POSTROUTING", "-s", str(link_subnet), "-o", uplink_iface, "-j", "MASQUERADE"],
        ]
        for cmd in removal_cmds:
            self.execute_command(cmd, check=False)

    def _remove_nat_firewall(self, namespace: str):
        self.execute_command(["ip", "netns", "exec", namespace, "iptables", "-F"], check=False)
        self.execute_command(["ip", "netns", "exec", namespace, "iptables", "-t", "nat", "-F"], check=False)
    
    def get_default_interface(self):
        """Get the default network interface"""
        result = self.execute_command(["ip", "route", "show", "default"])
        return result.stdout.split()[4]  # Extract interface name from default route
        
    
    def create_vpc(self, name: str, vpc_cidr: str = "10.0.0.0/16"):
        """Create a VPC with public/private subnets and a dedicated NAT namespace."""
        try:
            validate_vpc_name(name)
            validate_cidr(vpc_cidr)
            check_vpc_conflicts(name, list(self.vpcs.keys()))

            network = ipaddress.ip_network(vpc_cidr, strict=True)
            if network.prefixlen > 28:
                raise ValidationError("CIDR prefix must allow at least two /29 subnets")

            subnets = list(network.subnets(new_prefix=network.prefixlen + 1))
            if len(subnets) < 2:
                raise ValidationError("Unable to derive public and private subnets from CIDR")

            public_net, private_net = subnets[:2]

            def _gateway_and_host(subnet: ipaddress.IPv4Network) -> Tuple[str, str]:
                hosts_iter = subnet.hosts()
                gateway_ip = str(next(hosts_iter))
                host_ip = str(next(hosts_iter))
                return gateway_ip, host_ip

            public_gateway_ip, public_host_ip = _gateway_and_host(public_net)
            private_gateway_ip, private_host_ip = _gateway_and_host(private_net)

        except (ValidationError, ValueError) as exc:
            logger.error(f"Failed to validate VPC parameters: {exc}")
            raise NetworkInABoxError(f"Failed to validate VPC parameters: {exc}") from exc

        logger.info(f"Creating VPC {name} with CIDR {vpc_cidr}")

        bridge_name = f"br-{name}"
        nat_ns = f"{name}-nat"
        public_ns = f"{name}-public"
        private_ns = f"{name}-private"
        iface_tag = self._interface_tag(name)

        interfaces = {
            "public": {"ns": f"vn{iface_tag}p", "bridge": f"vb{iface_tag}p"},
            "private": {"ns": f"vn{iface_tag}r", "bridge": f"vb{iface_tag}r"},
            "nat_internal": {"ns": f"vn{iface_tag}g", "bridge": f"vb{iface_tag}g"},
            "nat_external": {"ns": f"vx{iface_tag}n", "host": f"vx{iface_tag}h"},
        }

        external_link = self._allocate_link_subnet(name)
        link_hosts = list(external_link.hosts())
        host_link_ip = str(link_hosts[0])
        nat_link_ip = str(link_hosts[1])

        default_interface = self.get_default_interface()

        # Create namespaces with baseline DNS settings
        self.create_namespace(public_ns, dns_servers=["8.8.8.8", "8.8.4.4"])
        self.create_namespace(private_ns, dns_servers=[private_gateway_ip])
        self.create_namespace(nat_ns)
        self.execute_command([
            "ip", "netns", "exec", nat_ns,
            "sysctl", "-w", "net.ipv4.ip_forward=1"
        ])

        # Create bridge
        self.create_bridge(bridge_name)

        # Configure NAT internal interface connected to bridge
        self.create_veth_pair(interfaces["nat_internal"]["ns"], interfaces["nat_internal"]["bridge"])
        self._configure_nat_internal_interface(
            nat_ns,
            interfaces["nat_internal"]["ns"],
            [
                f"{public_gateway_ip}/{public_net.prefixlen}",
                f"{private_gateway_ip}/{private_net.prefixlen}",
            ],
        )
        self.connect_veth_to_bridge(interfaces["nat_internal"]["bridge"], bridge_name)

        # Configure NAT external uplink via host
        self.create_veth_pair(interfaces["nat_external"]["ns"], interfaces["nat_external"]["host"])
        self._configure_nat_external_interface(
            nat_ns,
            interfaces["nat_external"]["ns"],
            f"{nat_link_ip}/{external_link.prefixlen}",
            host_link_ip,
        )

        host_ext_iface = interfaces["nat_external"]["host"]
        self.execute_command(["ip", "link", "set", host_ext_iface, "up"])
        self.execute_command(["ip", "addr", "flush", "dev", host_ext_iface])
        self.execute_command([
            "ip", "addr", "add", f"{host_link_ip}/{external_link.prefixlen}", "dev", host_ext_iface
        ])

        for subnet in (public_net, private_net):
            self.execute_command([
                "ip", "route", "replace", str(subnet), "via", nat_link_ip, "dev", host_ext_iface
            ], check=False)

        self._configure_nat_firewall(
            nat_ns,
            interfaces["nat_internal"]["ns"],
            interfaces["nat_external"]["ns"],
            [str(public_net), str(private_net)],
        )
        self._configure_host_firewall(host_ext_iface, default_interface, external_link)

        # Configure public namespace
        self.create_veth_pair(interfaces["public"]["ns"], interfaces["public"]["bridge"])
        self.setup_veth_in_namespace(
            interfaces["public"]["ns"],
            public_ns,
            f"{public_host_ip}/{public_net.prefixlen}",
            default_gateway=public_gateway_ip,
        )
        self.connect_veth_to_bridge(interfaces["public"]["bridge"], bridge_name)

        # Configure private namespace (no default route by default)
        self.create_veth_pair(interfaces["private"]["ns"], interfaces["private"]["bridge"])
        self.setup_veth_in_namespace(
            interfaces["private"]["ns"],
            private_ns,
            f"{private_host_ip}/{private_net.prefixlen}",
            routes=[{"dest": str(public_net), "via": private_gateway_ip}],
            default_gateway=None,
        )
        self.connect_veth_to_bridge(interfaces["private"]["bridge"], bridge_name)

        try:
            vpc_config = {
                "bridge": bridge_name,
                "vpc_cidr": vpc_cidr,
                "public_cidr": str(public_net),
                "private_cidr": str(private_net),
                "public_ns": public_ns,
                "private_ns": private_ns,
                "nat_ns": nat_ns,
                "interfaces": interfaces,
                "public_veth": [interfaces["public"]["ns"], interfaces["public"]["bridge"]],
                "private_veth": [interfaces["private"]["ns"], interfaces["private"]["bridge"]],
                "gateways": {
                    "public": public_gateway_ip,
                    "private": private_gateway_ip,
                    "link_subnet": str(external_link),
                    "host_link_ip": host_link_ip,
                    "nat_link_ip": nat_link_ip,
                    "uplink_interface": default_interface,
                },
                "private_outbound_enabled": False,
            }

            self.vpcs[name] = vpc_config
            self.state_manager.add_vpc(name, vpc_config)

            logger.info(f"VPC {name} created successfully")

        except Exception as exc:
            logger.error(f"Failed to save VPC state: {exc}")
            self.delete_vpc(name)
            raise

    def add_security_rule(self, namespace: str, protocol: str, port: int, source: str, action: str = "ACCEPT"):
        """Add a security group rule to a namespace"""
        try:
            # Validate all inputs
            validate_interface_name(namespace)
            validate_protocol(protocol)
            if protocol.lower() in ['tcp', 'udp']:
                validate_port(port)
            validate_cidr(source)
            validate_security_rule({
                'protocol': protocol,
                'port': port,
                'source': source,
                'action': action
            })
            
            if action not in ["ACCEPT", "DROP"]:
                raise ValidationError(f"Invalid action: {action}. Must be ACCEPT or DROP")
            
            logger.info(f"Adding {action} rule for {protocol}:{port} from {source} to {namespace}")
            
            # Create a new chain if it doesn't exist
            chain_name = f"NS_{namespace.replace('-', '_')}"
            self.execute_command(["ip", "netns", "exec", namespace, 
                "iptables", "-N", chain_name], check=False)
        except ValidationError as e:
            logger.error(str(e))
            raise NetworkInABoxError(f"Failed to validate security rule: {str(e)}")
        except ValueError as e:
            logger.error(str(e))
            raise NetworkInABoxError(f"Invalid parameter value: {str(e)}")
        
        # Build base command
        cmd = [
            "ip", "netns", "exec", namespace,
            "iptables", "-A", chain_name,
            "-p", protocol,
            "-s", source,
            "-j", action
        ]
        
        # Add port specification only for TCP/UDP
        if protocol.lower() in ['tcp', 'udp']:
            cmd.insert(-2, "--dport")
            cmd.insert(-2, str(port))
        
        # Add rule to the chain
        self.execute_command(cmd)
        
        # Ensure chain is used
        self.execute_command(["ip", "netns", "exec", namespace,
            "iptables", "-I", "INPUT", "1",
            "-j", chain_name
        ])
    
    def create_vpc_peering(self, vpc1_name: str, vpc2_name: str):
        """Create a peering connection between two VPCs using NAT-aware routing"""
        try:
            # Validate VPC names and existence
            validate_vpc_name(vpc1_name)
            validate_vpc_name(vpc2_name)
            
            if vpc1_name == vpc2_name:
                raise ValidationError("Cannot peer a VPC with itself")
                
            if vpc1_name not in self.vpcs:
                raise ResourceNotFoundError(f"VPC {vpc1_name} not found")
                
            if vpc2_name not in self.vpcs:
                raise ResourceNotFoundError(f"VPC {vpc2_name} not found")
                
            vpc1 = self.vpcs[vpc1_name]
            vpc2 = self.vpcs[vpc2_name]
            
            # Get CIDR blocks
            vpc1_cidr = vpc1.get('vpc_cidr')
            vpc2_cidr = vpc2.get('vpc_cidr')
            
            if not vpc1_cidr or not vpc2_cidr:
                raise ValidationError("Missing CIDR information in VPC configuration")
            
            # Check for CIDR conflicts
            if check_cidr_overlap(vpc1_cidr, vpc2_cidr):
                raise ValidationError(f"VPC CIDRs overlap: {vpc1_cidr} and {vpc2_cidr}")
            
            logger.info(f"Creating VPC peering between {vpc1_name} and {vpc2_name}")
        except ValidationError as e:
            logger.error(str(e))
            raise NetworkInABoxError(f"Failed to validate VPC peering parameters: {str(e)}")
        except ResourceNotFoundError as e:
            logger.error(str(e))
            raise
        
        # Create peering connection ID
        peer_id = f"{vpc1_name}-{vpc2_name}"
        
        # Allocate /30 link between NAT gateways for peering
        peer_link = self._allocate_peer_link_subnet(peer_id)
        peer_net = ipaddress.ip_network(peer_link)
        peer_hosts = list(peer_net.hosts())
        vpc1_peer_ip = str(peer_hosts[0])  # First host
        vpc2_peer_ip = str(peer_hosts[1])  # Second host
        
        # Create veth pair for NAT-to-NAT peering
        peer1_iface = f"vp{self._interface_tag(peer_id)}1"
        peer2_iface = f"vp{self._interface_tag(peer_id)}2"
        self.create_veth_pair(peer1_iface, peer2_iface)
        
        # Connect peering interfaces to NAT namespaces
        vpc1_nat_ns = vpc1['nat_ns']
        vpc2_nat_ns = vpc2['nat_ns']
        
        # Move peer interfaces to NAT namespaces
        self.execute_command(["ip", "link", "set", peer1_iface, "netns", vpc1_nat_ns])
        self.execute_command(["ip", "link", "set", peer2_iface, "netns", vpc2_nat_ns])
        
        # Configure peering interfaces in NAT namespaces
        self.execute_command([
            "ip", "netns", "exec", vpc1_nat_ns,
            "ip", "addr", "add", f"{vpc1_peer_ip}/{peer_net.prefixlen}",
            "dev", peer1_iface
        ])
        self.execute_command([
            "ip", "netns", "exec", vpc1_nat_ns,
            "ip", "link", "set", peer1_iface, "up"
        ])
        
        self.execute_command([
            "ip", "netns", "exec", vpc2_nat_ns,
            "ip", "addr", "add", f"{vpc2_peer_ip}/{peer_net.prefixlen}",
            "dev", peer2_iface
        ])
        self.execute_command([
            "ip", "netns", "exec", vpc2_nat_ns,
            "ip", "link", "set", peer2_iface, "up"
        ])
        
        # Add routes through NAT gateways for VPC-to-VPC communication
        self._add_nat_peering_routes(vpc1_name, vpc2_cidr, vpc2_peer_ip, peer1_iface)
        self._add_nat_peering_routes(vpc2_name, vpc1_cidr, vpc1_peer_ip, peer2_iface)
        
        # Store peering information
        peering_config = {
            'vpc1': vpc1_name,
            'vpc2': vpc2_name,
            'peer_link': peer_link,
            'vpc1_peer_ip': vpc1_peer_ip,
            'vpc2_peer_ip': vpc2_peer_ip,
            'interfaces': {
                'vpc1': peer1_iface,
                'vpc2': peer2_iface
            }
        }
        
        self.state_manager.add_peering(vpc1_name, vpc2_name, peering_config)
        
        logger.info(f"VPC peering established between {vpc1_name} and {vpc2_name}")
    
    def _allocate_peer_link_subnet(self, peer_id: str) -> str:
        """Allocate a /30 subnet for peering from 100.65.0.0/16 range"""
        import hashlib
        hash_obj = hashlib.sha1(peer_id.encode())
        hash_val = int(hash_obj.hexdigest()[:8], 16)
        
        # Use 100.65.0.0/16 for peering links (different from host links 100.64.0.0/16)
        subnet_offset = hash_val % 16384  # Max /30 subnets in /16
        base_ip = ipaddress.ip_address('100.65.0.0') + (subnet_offset * 4)
        return f"{base_ip}/30"
    
    def _add_nat_peering_routes(self, vpc_name: str, dest_cidr: str, next_hop: str, peer_iface: str):
        """Add routes in NAT namespace for peering traffic"""
        vpc = self.vpcs[vpc_name]
        nat_ns = vpc['nat_ns']
        nat_internal_iface = vpc['interfaces']['nat_internal']['ns']  # Get the actual interface name
        public_ns = vpc['public_ns']
        private_ns = vpc['private_ns']
        public_gw = vpc['gateways']['public']
        private_gw = vpc['gateways']['private']
        
        # Add route to destination VPC CIDR via peer interface in NAT namespace
        self.execute_command([
            "ip", "netns", "exec", nat_ns,
            "ip", "route", "add", dest_cidr,
            "via", next_hop, "dev", peer_iface
        ])
        
        # Add routes in public and private subnets to reach peered VPC via their gateways
        public_iface = vpc['interfaces']['public']['ns']
        private_iface = vpc['interfaces']['private']['ns']
        
        self.execute_command([
            "ip", "netns", "exec", public_ns,
            "ip", "route", "add", dest_cidr,
            "via", public_gw, "dev", public_iface
        ])
        
        self.execute_command([
            "ip", "netns", "exec", private_ns,
            "ip", "route", "add", dest_cidr,
            "via", private_gw, "dev", private_iface
        ])
        
        # Add forwarding rules in NAT namespace for peering traffic
        self.execute_command([
            "ip", "netns", "exec", nat_ns,
            "iptables", "-A", "FORWARD",
            "-i", nat_internal_iface, "-o", peer_iface,
            "-j", "ACCEPT"
        ], check=False)
        
        self.execute_command([
            "ip", "netns", "exec", nat_ns,
            "iptables", "-A", "FORWARD", 
            "-i", peer_iface, "-o", nat_internal_iface,
            "-j", "ACCEPT"
        ], check=False)
    
    def delete_vpc_peering(self, vpc1_name: str, vpc2_name: str):
        """Delete a peering connection between two VPCs"""
        try:
            # Validate VPC names
            validate_vpc_name(vpc1_name)
            validate_vpc_name(vpc2_name)
            
            if vpc1_name == vpc2_name:
                raise ValidationError("Cannot delete peering for a VPC with itself")
            
            logger.info(f"Deleting VPC peering between {vpc1_name} and {vpc2_name}")
        except ValidationError as e:
            logger.error(str(e))
            raise NetworkInABoxError(f"Failed to validate VPC peering parameters: {str(e)}")
        
        # Get peering configuration
        peering_config = self.state_manager.get_peering(vpc1_name, vpc2_name)
        if not peering_config:
            raise ResourceNotFoundError(f"Peering connection between {vpc1_name} and {vpc2_name} not found")
        
        # Extract peering information
        peer_link = peering_config.get('peer_link')
        vpc1_peer_ip = peering_config.get('vpc1_peer_ip')
        vpc2_peer_ip = peering_config.get('vpc2_peer_ip')
        interfaces = peering_config.get('interfaces', {})
        peer1_iface = interfaces.get('vpc1')
        peer2_iface = interfaces.get('vpc2')
        
        # Get VPC configurations
        vpc1 = self.vpcs.get(vpc1_name)
        vpc2 = self.vpcs.get(vpc2_name)
        
        if vpc1 and vpc2:
            vpc1_nat_ns = vpc1['nat_ns']
            vpc2_nat_ns = vpc2['nat_ns']
            vpc1_cidr = vpc1.get('vpc_cidr')
            vpc2_cidr = vpc2.get('vpc_cidr')
            vpc1_nat_internal_iface = vpc1['interfaces']['nat_internal']['ns']
            vpc2_nat_internal_iface = vpc2['interfaces']['nat_internal']['ns']
            
            # Remove routes from NAT namespaces
            if vpc1_cidr and vpc2_peer_ip:
                self.execute_command([
                    "ip", "netns", "exec", vpc1_nat_ns,
                    "ip", "route", "del", vpc2_cidr
                ], check=False)
            
            if vpc2_cidr and vpc1_peer_ip:
                self.execute_command([
                    "ip", "netns", "exec", vpc2_nat_ns,
                    "ip", "route", "del", vpc1_cidr
                ], check=False)
            
            # Remove routes from public and private subnets
            if vpc2_cidr:
                self.execute_command([
                    "ip", "netns", "exec", vpc1['public_ns'],
                    "ip", "route", "del", vpc2_cidr
                ], check=False)
                self.execute_command([
                    "ip", "netns", "exec", vpc1['private_ns'],
                    "ip", "route", "del", vpc2_cidr
                ], check=False)
            
            if vpc1_cidr:
                self.execute_command([
                    "ip", "netns", "exec", vpc2['public_ns'],
                    "ip", "route", "del", vpc1_cidr
                ], check=False)
                self.execute_command([
                    "ip", "netns", "exec", vpc2['private_ns'],
                    "ip", "route", "del", vpc1_cidr
                ], check=False)
            
            # Remove iptables forwarding rules
            if peer1_iface:
                self.execute_command([
                    "ip", "netns", "exec", vpc1_nat_ns,
                    "iptables", "-D", "FORWARD",
                    "-i", vpc1_nat_internal_iface, "-o", peer1_iface,
                    "-j", "ACCEPT"
                ], check=False)
                
                self.execute_command([
                    "ip", "netns", "exec", vpc1_nat_ns,
                    "iptables", "-D", "FORWARD",
                    "-i", peer1_iface, "-o", vpc1_nat_internal_iface,
                    "-j", "ACCEPT"
                ], check=False)
            
            if peer2_iface:
                self.execute_command([
                    "ip", "netns", "exec", vpc2_nat_ns,
                    "iptables", "-D", "FORWARD",
                    "-i", vpc2_nat_internal_iface, "-o", peer2_iface,
                    "-j", "ACCEPT"
                ], check=False)
                
                self.execute_command([
                    "ip", "netns", "exec", vpc2_nat_ns,
                    "iptables", "-D", "FORWARD",
                    "-i", peer2_iface, "-o", vpc2_nat_internal_iface,
                    "-j", "ACCEPT"
                ], check=False)
        
        # Delete peer interfaces (they will be removed when namespaces are destroyed)
        # The veth pair is automatically cleaned up when one end is deleted
        
        # Remove from state
        self.state_manager.remove_peering(vpc1_name, vpc2_name)
        
        logger.info(f"VPC peering between {vpc1_name} and {vpc2_name} deleted successfully")
    
    
    def deploy_test_server(self, namespace: str, server_type: str = "python", port: int = 8080) -> Tuple[bool, Optional[str]]:
        """Deploy a test server in the specified namespace"""
        # Validate namespace exists
        result = self.execute_command(["ip", "netns", "list"], check=False)
        if namespace not in result.stdout:
            return False, f"Namespace {namespace} does not exist"
            
        # Validate port
        try:
            validate_port(port)
        except ValidationError as e:
            return False, str(e)
        
        # Deploy server based on type
        if server_type.lower() == "python":
            return self.test_server.deploy_python_http(namespace, port)
        elif server_type.lower() == "nginx":
            return self.test_server.deploy_nginx(namespace, port)
        else:
            return False, f"Unsupported server type: {server_type}"
    
    def stop_test_server(self, namespace: str) -> Tuple[bool, Optional[str]]:
        """Stop the test server in the specified namespace"""
        return self.test_server.stop_server(namespace)
    
    def test_connectivity(self, source_ns: str, target_ns: str, target_port: int) -> Tuple[bool, Optional[str]]:
        """Test connectivity between namespaces"""
        try:
            # Ensure both namespaces exist
            for ns in [source_ns, target_ns]:
                result = self.execute_command(["ip", "netns", "list"], check=False)
                if ns not in result.stdout:
                    return False, f"Namespace {ns} does not exist"
            
            # Try to connect using curl
            cmd = [
                "ip", "netns", "exec", source_ns,
                "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                f"http://{self._get_namespace_ip(target_ns)}:{target_port}"
            ]
            
            result = self.execute_command(cmd, check=False)
            if result.returncode == 0 and result.stdout.strip() == "200":
                return True, None
            else:
                return False, f"Connection failed: {result.stderr}"
                
        except Exception as e:
            return False, f"Test failed: {str(e)}"
    
    def _get_namespace_ip(self, namespace: str) -> Optional[str]:
        """Get the IP address of a namespace's interface"""
        try:
            result = self.execute_command([
                "ip", "netns", "exec", namespace,
                "ip", "-j", "addr", "show"
            ])
            
            import json
            addrs = json.loads(result.stdout)
            for iface in addrs:
                if iface["ifname"].startswith("veth"):
                    for addr in iface.get("addr_info", []):
                        if addr["family"] == "inet":
                            return addr["local"]
            return None
        except Exception:
            return None
    
    def delete_vpc(self, name: str):
        """Delete a VPC and all its components"""
        try:
            # Validate VPC name and existence 
            validate_vpc_name(name)
            if name not in self.vpcs:
                # Try to clean up any orphaned resources even if not in state
                logger.warning(f"VPC {name} not found in state, attempting cleanup anyway")
                self._cleanup_orphaned_vpc_resources(name)
                return
            
            logger.info(f"Deleting VPC: {name}")
            vpc_config = self.vpcs[name]
            
            bridge_name = vpc_config['bridge']
            public_ns = vpc_config['public_ns']
            private_ns = vpc_config['private_ns']
            nat_ns = vpc_config.get('nat_ns')
            interfaces = vpc_config.get('interfaces', {})
            gateways = vpc_config.get('gateways', {})
        except ValidationError as e:
            logger.error(f"Invalid VPC name: {str(e)}")
            raise NetworkInABoxError(f"Failed to validate VPC name: {str(e)}")
        except Exception as e:
            # If we can't get config, try cleanup anyway
            logger.warning(f"Could not get VPC config: {e}, attempting cleanup")
            self._cleanup_orphaned_vpc_resources(name)
            return
        
        host_iface = interfaces.get('nat_external', {}).get('host')
        uplink_iface = gateways.get('uplink_interface', self.get_default_interface())
        link_subnet = gateways.get('link_subnet')

        if nat_ns:
            self._remove_nat_firewall(nat_ns)

        if host_iface and link_subnet:
            try:
                self._remove_host_firewall(host_iface, uplink_iface, ipaddress.ip_network(link_subnet))
            except ValueError:
                logger.warning("Could not parse link subnet during teardown")

        # Delete namespaces (interfaces inside are cleaned automatically)
        for ns in [public_ns, private_ns, nat_ns]:
            if ns:
                self.execute_command(["ip", "netns", "del", ns], check=False)

        # Remove host routes to VPC subnets
        nat_link_ip = gateways.get('nat_link_ip')
        if host_iface and nat_link_ip:
            for subnet_key in ['public_cidr', 'private_cidr']:
                subnet = vpc_config.get(subnet_key)
                if subnet:
                    self.execute_command([
                        "ip", "route", "del", subnet, "via", nat_link_ip, "dev", host_iface
                    ], check=False)

        # Delete host-side interfaces
        for iface in filter(None, [host_iface, interfaces.get('public', {}).get('bridge'),
                                   interfaces.get('private', {}).get('bridge'),
                                   interfaces.get('nat_internal', {}).get('bridge')]):
            self.execute_command(["ip", "link", "del", iface], check=False)

        # Delete bridge
        self.execute_command(["ip", "link", "del", bridge_name], check=False)

        # Remove from state
        try:
            self.state_manager.remove_vpc(name)
        except StateError as exc:
            logger.warning(f"State removal warning: {exc}")

        if name in self.vpcs:
            del self.vpcs[name]

        logger.info(f"VPC {name} deleted successfully")

    def _cleanup_orphaned_vpc_resources(self, name: str):
        """Clean up VPC resources that might exist without state entry."""
        logger.info(f"Attempting orphaned resource cleanup for {name}")
        
        # Try to delete common namespaces
        for suffix in ["-public", "-private", "-nat"]:
            ns_name = f"{name}{suffix}"
            self.execute_command(["ip", "netns", "del", ns_name], check=False)
        
        # Try to delete bridge
        bridge_name = f"br-{name}"
        self.execute_command(["ip", "link", "del", bridge_name], check=False)
        
        # Try to delete common interface patterns
        iface_tag = self._interface_tag(name)
        for prefix in ["vn", "vb", "vx"]:
            for suffix in ["p", "r", "g", "h", "n"]:
                iface_name = f"{prefix}{iface_tag}{suffix}"
                self.execute_command(["ip", "link", "del", iface_name], check=False)
        
        logger.info(f"Orphaned resource cleanup completed for {name}")

def main():
    parser = argparse.ArgumentParser(description="Network-in-a-Box: A VPC simulation tool")
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # create-vpc command
    create_vpc_parser = subparsers.add_parser("create-vpc", help="Create a new VPC")
    create_vpc_parser.add_argument("--name", required=True, help="Name of the VPC")
    create_vpc_parser.add_argument("--cidr", default="10.0.0.0/16", help="CIDR block for the VPC")
    
    # delete-vpc command
    delete_vpc_parser = subparsers.add_parser("delete-vpc", help="Delete one or more VPCs")
    delete_vpc_parser.add_argument("--name", required=True, help="Name of the VPC", action="append", dest="names")
    
    # add-security-rule command
    security_parser = subparsers.add_parser("add-security-rule", help="Add a security rule to a namespace")
    security_parser.add_argument("--namespace", required=True, help="Target namespace")
    security_parser.add_argument("--protocol", required=True, help="Protocol (tcp/udp)")
    security_parser.add_argument("--port", required=True, type=int, help="Port number")
    security_parser.add_argument("--source", required=True, help="Source CIDR")
    security_parser.add_argument("--action", choices=["ACCEPT", "DROP"], default="ACCEPT", help="Rule action")
    
    # create-vpc-peering command
    peering_parser = subparsers.add_parser("create-vpc-peering", help="Create VPC peering connection")
    peering_parser.add_argument("--vpc1", required=True, help="First VPC name")
    peering_parser.add_argument("--vpc2", required=True, help="Second VPC name")
    
    # delete-vpc-peering command
    delete_peering_parser = subparsers.add_parser("delete-vpc-peering", help="Delete VPC peering connection")
    delete_peering_parser.add_argument("--vpc1", required=True, help="First VPC name")
    delete_peering_parser.add_argument("--vpc2", required=True, help="Second VPC name")
    
    # apply-policy command
    policy_parser = subparsers.add_parser("apply-policy", help="Apply a security policy to a namespace")
    policy_parser.add_argument("--namespace", required=True, help="Target namespace")
    policy_parser.add_argument("--policy-file", required=True, help="JSON policy file to apply")
    
    # deploy-server command
    server_parser = subparsers.add_parser("deploy-server", help="Deploy a test server in a namespace")
    server_parser.add_argument("--namespace", required=True, help="Target namespace")
    server_parser.add_argument("--type", choices=["python", "nginx"], default="python", help="Server type")
    server_parser.add_argument("--port", type=int, default=8080, help="Server port")
    
    # stop-server command
    stop_server_parser = subparsers.add_parser("stop-server", help="Stop a test server in a namespace")
    stop_server_parser.add_argument("--namespace", required=True, help="Target namespace")
    
    # test-connectivity command
    test_parser = subparsers.add_parser("test-connectivity", help="Test connectivity between namespaces")
    test_parser.add_argument("--source", required=True, help="Source namespace")
    test_parser.add_argument("--target", required=True, help="Target namespace")
    test_parser.add_argument("--port", type=int, default=8080, help="Target port")
    
    # validate-vpc-isolation command
    isolation_parser = subparsers.add_parser("validate-vpc-isolation", help="Validate VPC isolation")
    isolation_parser.add_argument("--vpc1", required=True, help="First VPC name")
    isolation_parser.add_argument("--vpc2", required=True, help="Second VPC name")
    
    # validate-nat command
    nat_parser = subparsers.add_parser("validate-nat", help="Validate NAT behavior")
    nat_parser.add_argument("--namespace", required=True, help="Namespace to validate")
    
    # validate-security command
    security_parser = subparsers.add_parser("validate-security", help="Validate security rules")
    security_parser.add_argument("--namespace", required=True, help="Namespace to validate")
    security_parser.add_argument("--rules", required=True, help="JSON file containing security rules")
    
    args = parser.parse_args()
    
    try:
        network = NetworkInABox()
        
        if args.command == "create-vpc":
            network.create_vpc(args.name, args.cidr)
        elif args.command == "delete-vpc":
            for vpc_name in args.names:
                try:
                    network.delete_vpc(vpc_name)
                except Exception as e:
                    logger.error(f"Failed to delete VPC {vpc_name}: {e}")
                    sys.exit(1)
        elif args.command == "add-security-rule":
            network.add_security_rule(
                args.namespace,
                args.protocol,
                args.port,
                args.source,
                args.action
            )
        elif args.command == "create-vpc-peering":
            network.create_vpc_peering(args.vpc1, args.vpc2)
        elif args.command == "delete-vpc-peering":
            network.delete_vpc_peering(args.vpc1, args.vpc2)
        elif args.command == "apply-policy":
            try:
                policy = network.policy_manager.load_policy(args.policy_file)
                network.policy_manager.apply_policy(args.namespace, policy)
                logger.info(f"Successfully applied policy from {args.policy_file} to {args.namespace}")
            except Exception as e:
                logger.error(f"Failed to apply policy: {e}")
                sys.exit(1)
        elif args.command == "deploy-server":
            success, error = network.deploy_test_server(args.namespace, args.type, args.port)
            if not success:
                logger.error(f"Failed to deploy server: {error}")
                sys.exit(1)
            logger.info(f"Successfully deployed {args.type} server in {args.namespace} on port {args.port}")
        elif args.command == "stop-server":
            success, error = network.stop_test_server(args.namespace)
            if not success:
                logger.error(f"Failed to stop server: {error}")
                sys.exit(1)
            logger.info(f"Successfully stopped server in {args.namespace}")
        elif args.command == "test-connectivity":
            success, error = network.test_connectivity(args.source, args.target, args.port)
            if not success:
                logger.error(f"Connectivity test failed: {error}")
                sys.exit(1)
            logger.info(f"Successfully connected from {args.source} to {args.target} on port {args.port}")
        elif args.command == "validate-vpc-isolation":
            success, error = network.validator.validate_vpc_isolation(args.vpc1, args.vpc2)
            if not success:
                logger.error(f"VPC isolation validation failed: {error}")
                sys.exit(1)
            logger.info(f"VPC isolation validated successfully between {args.vpc1} and {args.vpc2}")
        elif args.command == "validate-nat":
            success, results = network.validator.validate_nat_behavior(args.namespace)
            if not success:
                logger.error(f"NAT validation failed for {args.namespace}")
                for test, result in results.items():
                    logger.error(f"{test}: {'PASS' if result else 'FAIL'}")
                sys.exit(1)
            logger.info(f"NAT validation successful for {args.namespace}")
            for test, result in results.items():
                logger.info(f"{test}: {'PASS' if result else 'FAIL'}")
        elif args.command == "validate-security":
            try:
                with open(args.rules) as f:
                    rules = json.load(f)
            except Exception as e:
                logger.error(f"Failed to load rules file: {e}")
                sys.exit(1)
            
            success, results = network.validator.validate_security_rules(args.namespace, rules)
            if not success:
                logger.error(f"Security validation failed for {args.namespace}")
                for rule, result in results.items():
                    logger.error(f"{rule}: {'PASS' if result else 'FAIL'}")
                sys.exit(1)
            logger.info(f"Security validation successful for {args.namespace}")
            for rule, result in results.items():
                logger.info(f"{rule}: {'PASS' if result else 'FAIL'}")
        else:
            parser.print_help()
            
    except Exception as e:
        logger.error(f"An error occurred: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()