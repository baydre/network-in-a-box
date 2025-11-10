"""Policy management for Network-in-a-Box."""

import json
import logging
import os
from typing import Dict, List, Optional
from exceptions import ValidationError
from validation import (
    validate_cidr,
    validate_port,
    validate_protocol
)

logger = logging.getLogger(__name__)

class PolicyManager:
    """Manages security policies for VPC subnets."""

    def __init__(self, policy_dir: str = "policies"):
        """Initialize the policy manager."""
        self.policy_dir = policy_dir
        if not os.path.exists(policy_dir):
            os.makedirs(policy_dir)

    def load_policy(self, policy_file: str) -> Dict:
        """Load a policy from a JSON file."""
        try:
            # Check if it's an absolute path or relative to policy_dir
            if os.path.isabs(policy_file):
                file_path = policy_file
            else:
                file_path = os.path.join(self.policy_dir, policy_file)
                
            with open(file_path) as f:
                policy = json.load(f)
            self._validate_policy(policy)
            return policy
        except FileNotFoundError:
            logger.error(f"Policy file not found: {policy_file}")
            raise
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in policy file: {e}")
            raise
        except ValidationError as e:
            logger.error(f"Invalid policy configuration: {e}")
            raise

    def _validate_policy(self, policy: Dict) -> None:
        """Validate policy structure and values."""
        required_fields = {"subnet"}
        if not all(field in policy for field in required_fields):
            raise ValidationError(f"Missing required fields: {required_fields - set(policy.keys())}")

        # Validate subnet CIDR
        validate_cidr(policy["subnet"])

        # Validate ingress rules
        if "ingress" in policy:
            for rule in policy["ingress"]:
                self._validate_rule(rule)

        # Validate egress rules
        if "egress" in policy:
            for rule in policy["egress"]:
                self._validate_rule(rule)

    def _validate_rule(self, rule: Dict) -> None:
        """Validate a single rule in the policy."""
        required_fields = {"protocol", "action"}
        if not all(field in rule for field in required_fields):
            raise ValidationError(f"Missing required fields in rule: {required_fields - set(rule.keys())}")

        # Validate protocol
        if rule["protocol"] != "all":
            validate_protocol(rule["protocol"])

        # Validate port if specified
        if "port" in rule and rule["port"] != "all":
            validate_port(int(rule["port"]))

        # Validate CIDR if specified
        if "source" in rule:
            validate_cidr(rule["source"])
        if "destination" in rule:
            validate_cidr(rule["destination"])

        # Validate action
        if rule["action"] not in ["allow", "deny", "ACCEPT", "DROP"]:
            raise ValidationError(f"Invalid action: {rule['action']}. Must be 'allow', 'deny', 'ACCEPT', or 'DROP'")

    def apply_policy(self, namespace: str, policy: Dict) -> None:
        """Apply a policy to a network namespace."""
        logger.info(f"Applying policy to namespace {namespace}")
        
        # Convert policy rules to iptables commands
        if "ingress" in policy:
            for rule in policy["ingress"]:
                self._apply_rule(namespace, rule, direction="ingress")
                
        if "egress" in policy:
            for rule in policy["egress"]:
                self._apply_rule(namespace, rule, direction="egress")
    
    def _reset_namespace_rules(self, namespace: str) -> None:
        """Reset iptables rules in namespace to clean state."""
        import subprocess
        
        # Flush all user-defined rules
        for table in ["filter"]:
            for chain in ["INPUT", "OUTPUT", "FORWARD"]:
                cmd = [
                    "ip", "netns", "exec", namespace,
                    "iptables", "-t", table, "-F", chain
                ]
                try:
                    subprocess.run(cmd, check=True, capture_output=True, text=True)
                except subprocess.CalledProcessError as e:
                    logger.warning(f"Failed to flush {chain} chain: {e.stderr}")
    
    def _set_default_policies(self, namespace: str) -> None:
        """Set default policies for chains."""
        import subprocess
        
        # Set default policies to DROP for security
        for chain in ["INPUT", "OUTPUT", "FORWARD"]:
            cmd = [
                "ip", "netns", "exec", namespace,
                "iptables", "-P", chain, "DROP"
            ]
            try:
                subprocess.run(cmd, check=True, capture_output=True, text=True)
            except subprocess.CalledProcessError as e:
                logger.warning(f"Failed to set default policy for {chain}: {e.stderr}")
        
        # Allow loopback traffic (always needed)
        for direction in ["-i", "-o"]:
            cmd = [
                "ip", "netns", "exec", namespace,
                "iptables", "-A", "INPUT" if direction == "-i" else "OUTPUT",
                direction, "lo", "-j", "ACCEPT"
            ]
            try:
                subprocess.run(cmd, check=True, capture_output=True, text=True)
            except subprocess.CalledProcessError as e:
                logger.warning(f"Failed to allow loopback traffic: {e.stderr}")
        
        # Allow established connections
        cmd = [
            "ip", "netns", "exec", namespace,
            "iptables", "-A", "INPUT",
            "-m", "state", "--state", "ESTABLISHED,RELATED", 
            "-j", "ACCEPT"
        ]
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            logger.warning(f"Failed to allow established connections: {e.stderr}")

    def _apply_rule(self, namespace: str, rule: Dict, direction: str) -> None:
        """Apply a single rule using iptables."""
        import subprocess
        
        # Build iptables command based on rule
        chain = "INPUT" if direction == "ingress" else "OUTPUT"
        
        # Map action to iptables target
        action = rule["action"].lower()
        if action in ["allow", "accept"]:
            target = "ACCEPT"
        elif action in ["deny", "drop"]:
            target = "DROP"
        else:
            target = rule["action"]  # Use as-is if already iptables format
        
        cmd = [
            "ip", "netns", "exec", namespace,
            "iptables", "-A", chain
        ]

        # Add protocol if specified
        if rule["protocol"] != "all":
            cmd.extend(["-p", rule["protocol"]])

        # Add port if specified
        if "port" in rule and rule["port"] != "all":
            port_str = str(rule["port"])
            if direction == "ingress":
                cmd.extend(["--dport", port_str])
            else:
                cmd.extend(["--sport", port_str])

        # Add source/destination if specified
        if direction == "ingress" and "source" in rule:
            cmd.extend(["-s", rule["source"]])
        elif direction == "egress" and "destination" in rule:
            cmd.extend(["-d", rule["destination"]])

        # Add target (ACCEPT/DROP)
        cmd.extend(["-j", target])

        logger.info(f"Applying security rule: {' '.join(cmd[4:])}")  # Log without namespace prefix
        
        # Execute the command
        try:
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            if result.stdout:
                logger.debug(f"Rule applied successfully: {result.stdout}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to apply rule: {e.stderr}")
            raise ValidationError(f"Failed to apply iptables rule: {e.stderr}")
    
    def list_rules(self, namespace: str) -> Dict:
        """List current iptables rules in a namespace."""
        import subprocess
        
        rules = {"INPUT": [], "OUTPUT": [], "FORWARD": []}
        
        for chain in rules.keys():
            cmd = [
                "ip", "netns", "exec", namespace,
                "iptables", "-L", chain, "-n", "-v"
            ]
            try:
                result = subprocess.run(cmd, check=True, capture_output=True, text=True)
                rules[chain] = result.stdout.split('\n')
            except subprocess.CalledProcessError as e:
                logger.warning(f"Failed to list {chain} rules: {e.stderr}")
                
        return rules
    
    def remove_policy(self, namespace: str) -> None:
        """Remove all custom policies from a namespace (reset to permissive)."""
        import subprocess
        
        logger.info(f"Removing policies from namespace {namespace}")
        
        # Reset to permissive defaults
        for chain in ["INPUT", "OUTPUT", "FORWARD"]:
            # Flush rules
            cmd = ["ip", "netns", "exec", namespace, "iptables", "-F", chain]
            try:
                subprocess.run(cmd, check=True, capture_output=True, text=True)
            except subprocess.CalledProcessError as e:
                logger.warning(f"Failed to flush {chain}: {e.stderr}")
            
            # Set permissive policy
            cmd = ["ip", "netns", "exec", namespace, "iptables", "-P", chain, "ACCEPT"]
            try:
                subprocess.run(cmd, check=True, capture_output=True, text=True)
            except subprocess.CalledProcessError as e:
                logger.warning(f"Failed to set permissive policy for {chain}: {e.stderr}")