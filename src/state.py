"""State management for Network-in-a-Box."""

import json
import os
import logging
import fcntl
from typing import Dict, Optional
from exceptions import StateError

logger = logging.getLogger(__name__)

class StateManager:
    """Manages the persistent state of Network-in-a-Box."""

    def __init__(self, state_file: str = "/var/tmp/network_in_a_box.state"):
        """Initialize the state manager."""
        self.state_file = state_file
        # Ensure state directory exists
        os.makedirs(os.path.dirname(state_file), exist_ok=True)
        self._state = self._load_state()

    def _load_state(self) -> Dict:
        """Load state from file with file locking."""
        try:
            if os.path.exists(self.state_file):
                try:
                    with open(self.state_file, 'r') as f:
                        # Acquire a shared lock for reading
                        fcntl.flock(f.fileno(), fcntl.LOCK_SH)
                        try:
                            state_data = json.loads(f.read())
                        finally:
                            # Always release the lock
                            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                            
                        # Validate state structure
                        if not isinstance(state_data, dict):
                            raise StateError("Invalid state format: root must be an object")
                        # Ensure required keys exist
                        if 'vpcs' not in state_data or 'peering_connections' not in state_data:
                            state_data = {'vpcs': {}, 'peering_connections': {}}
                            self.save_state(state_data)
                        return state_data
                except json.JSONDecodeError as e:
                    logger.error(f"Corrupt state file, recreating: {e}")
                    os.remove(self.state_file)
                    return {'vpcs': {}, 'peering_connections': {}}
            return {'vpcs': {}, 'peering_connections': {}}
        except Exception as e:
            logger.error(f"Failed to load state: {e}")
            return {'vpcs': {}, 'peering_connections': {}}

    def save_state(self, state=None) -> None:
        """Save current state to file with file locking for atomicity."""
        if state is not None:
            self._state = state
            
        try:
            # Open file in read+write mode
            with open(self.state_file, 'r+' if os.path.exists(self.state_file) else 'w+') as f:
                # Acquire an exclusive lock
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                try:
                    # Truncate file
                    f.seek(0)
                    f.truncate()
                    # Write new state
                    json.dump(self._state, f, indent=2)
                    # Flush to disk
                    f.flush()
                    os.fsync(f.fileno())
                finally:
                    # Always release the lock
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except Exception as e:
            logger.error(f"Failed to save state: {e}")
            raise StateError(f"Failed to save state: {str(e)}")

    def get_vpc(self, vpc_name: str) -> Optional[Dict]:
        """Get VPC configuration."""
        return self._state['vpcs'].get(vpc_name)

    def get_all_vpcs(self) -> Dict:
        """Get all VPC configurations."""
        return self._state.get('vpcs', {})

    def add_vpc(self, vpc_name: str, config: Dict) -> None:
        """Add a new VPC configuration. Overwrites if already exists."""
        if vpc_name in self._state['vpcs']:
            logger.warning(f"VPC {vpc_name} already exists in state, overwriting")
        self._state['vpcs'][vpc_name] = config
        self.save_state()

    def remove_vpc(self, vpc_name: str) -> None:
        """Remove a VPC configuration."""
        try:
            logger.debug(f"Removing VPC {vpc_name} from state")
            logger.debug(f"Current state before removal: {self._state}")
            
            # Open file in read+write mode with exclusive lock
            with open(self.state_file, 'r+') as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                try:
                    # Read current state
                    f.seek(0)
                    file_content = f.read()
                    logger.debug(f"Read from state file: {file_content}")
                    current_state = json.loads(file_content)
                    logger.debug(f"Parsed state: {current_state}")
                    
                    if vpc_name not in current_state['vpcs']:
                        raise StateError(f"VPC {vpc_name} not found in state")
                    
                    logger.debug(f"Found VPC {vpc_name} in state")
                    # Remove the VPC while preserving other state
                    del current_state['vpcs'][vpc_name]
                    logger.debug(f"State after removal: {current_state}")
                    
                    # Write updated state
                    f.seek(0)
                    f.truncate()
                    json.dump(current_state, f, indent=2)
                    f.flush()
                    os.fsync(f.fileno())
                    
                    # Update in-memory state
                    self._state = current_state
                    logger.debug(f"Updated in-memory state: {self._state}")
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except FileNotFoundError:
            logger.error(f"State file not found")
            raise StateError(f"State file not found")
        except json.JSONDecodeError as e:
            logger.error(f"Invalid state file format: {e}")
            raise StateError(f"Invalid state file format: {e}")
        except Exception as e:
            logger.error(f"Failed to remove VPC: {e}")
            raise StateError(f"Failed to remove VPC: {e}")
        
    def add_peering(self, vpc1: str, vpc2: str, config: Dict) -> None:
        """Add a VPC peering connection."""
        peering_id = f"{vpc1}-to-{vpc2}"
        if peering_id in self._state['peering_connections']:
            raise StateError(f"Peering connection {peering_id} already exists")
        self._state['peering_connections'][peering_id] = config
        self.save_state()

    def remove_peering(self, vpc1: str, vpc2: str) -> None:
        """Remove a VPC peering connection."""
        peering_id = f"{vpc1}-to-{vpc2}"
        if peering_id not in self._state['peering_connections']:
            raise StateError(f"Peering connection {peering_id} not found")
        del self._state['peering_connections'][peering_id]
        self.save_state()

    def get_peering(self, vpc1: str, vpc2: str) -> Optional[Dict]:
        """Get peering connection configuration."""
        peering_id = f"{vpc1}-to-{vpc2}"
        return self._state['peering_connections'].get(peering_id)

    def get_all_peerings(self) -> Dict:
        """Get all peering connections."""
        return self._state.get('peering_connections', {})
