"""Monitoring utilities for Network-in-a-Box."""

import json
import subprocess
from typing import Dict, List, Optional
from exceptions import NetworkConfigError

class NetworkMonitor:
    """Monitors network components and provides status information."""

    @staticmethod
    def _run_command(command: List[str]) -> str:
        """Run a command and return its output."""
        try:
            result = subprocess.run(command, check=True, capture_output=True, text=True)
            return result.stdout
        except subprocess.CalledProcessError as e:
            raise NetworkConfigError(f"Command failed: {e.stderr}")

    def get_namespace_status(self, namespace: str) -> Dict:
        """Get status of a network namespace."""
        try:
            # Check if namespace exists
            self._run_command(['ip', 'netns', 'list'])
            
            # Get interface information
            interfaces = self._run_command([
                'ip', 'netns', 'exec', namespace, 'ip', '-j', 'addr', 'show'
            ])
            
            # Get routing information
            routes = self._run_command([
                'ip', 'netns', 'exec', namespace, 'ip', '-j', 'route', 'show'
            ])
            
            # Get iptables rules
            iptables = self._run_command([
                'ip', 'netns', 'exec', namespace, 'iptables-save'
            ])

            return {
                'status': 'active',
                'interfaces': json.loads(interfaces),
                'routes': json.loads(routes),
                'iptables': iptables.split('\\n')
            }
        except NetworkConfigError:
            return {'status': 'not-found'}
        except json.JSONDecodeError:
            return {'status': 'error', 'message': 'Failed to parse network information'}

    def get_bridge_status(self, bridge: str) -> Dict:
        """Get status of a bridge interface."""
        try:
            # Get bridge information
            bridge_info = self._run_command(['ip', '-j', 'link', 'show', bridge])
            
            # Get bridge addresses
            addr_info = self._run_command(['ip', '-j', 'addr', 'show', bridge])
            
            # Get bridge forwarding database
            fdb_info = self._run_command(['bridge', 'fdb', 'show', 'dev', bridge])

            return {
                'status': 'active',
                'link': json.loads(bridge_info),
                'addresses': json.loads(addr_info),
                'fdb': fdb_info.split('\\n')
            }
        except NetworkConfigError:
            return {'status': 'not-found'}
        except json.JSONDecodeError:
            return {'status': 'error', 'message': 'Failed to parse bridge information'}

    def get_vpc_status(self, vpc_config: Dict) -> Dict:
        """Get comprehensive status of a VPC."""
        status = {
            'bridge': self.get_bridge_status(vpc_config['bridge']),
            'public_subnet': self.get_namespace_status(vpc_config['public_ns']),
            'private_subnet': self.get_namespace_status(vpc_config['private_ns']),
            'internet_connectivity': self._check_internet_connectivity(vpc_config['public_ns'])
        }
        
        return status

    def _check_internet_connectivity(self, namespace: str) -> Dict:
        """Check if a namespace has internet connectivity."""
        try:
            # Try to ping Google's DNS
            result = self._run_command([
                'ip', 'netns', 'exec', namespace,
                'ping', '-c', '1', '-W', '2', '8.8.8.8'
            ])
            return {'status': 'connected', 'latency': self._parse_ping_latency(result)}
        except NetworkConfigError:
            return {'status': 'disconnected'}

    def _parse_ping_latency(self, ping_output: str) -> float:
        """Parse ping command output to get latency."""
        try:
            for line in ping_output.split('\\n'):
                if 'time=' in line:
                    return float(line.split('time=')[1].split()[0])
            return 0.0
        except (IndexError, ValueError):
            return 0.0