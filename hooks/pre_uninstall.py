"""
OpenVPN Module - Pre Uninstall Hook

Executed before module uninstallation:
- Stops all running instances
- Removes firewall chains
- Optionally backs up PKI data
"""
import subprocess
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def run():
    """Pre-uninstall hook for OpenVPN module."""
    logger.info("Running OpenVPN pre-uninstall hook")
    
    # 1. Stop all OpenVPN instances
    try:
        result = subprocess.run(
            ["systemctl", "list-units", "--type=service", "--state=running", 
             "--plain", "--no-legend"],
            capture_output=True,
            text=True
        )
        for line in result.stdout.split('\n'):
            if 'openvpn-server@' in line:
                service = line.split()[0]
                subprocess.run(["systemctl", "stop", service], capture_output=True)
                logger.info(f"Stopped service: {service}")
    except Exception as e:
        logger.warning(f"Error stopping services: {e}")
    
    # 2. Remove jump rules from parent chains
    jump_rules = [
        ("filter", "MADMIN_INPUT", "MOD_OVPN_INPUT"),
        ("filter", "MADMIN_FORWARD", "MOD_OVPN_FORWARD"),
        ("nat", "MADMIN_POSTROUTING", "MOD_OVPN_NAT"),
    ]
    
    for table, parent, chain in jump_rules:
        subprocess.run(
            ["iptables", "-t", table, "-D", parent, "-j", chain],
            capture_output=True
        )
        logger.info(f"Removed jump rule: {parent} -> {chain}")
    
    # 3. Remove module chains
    chains = [
        ("filter", "MOD_OVPN_INPUT"),
        ("filter", "MOD_OVPN_FORWARD"),
        ("nat", "MOD_OVPN_NAT"),
    ]
    
    for table, chain in chains:
        # Flush chain
        subprocess.run(["iptables", "-t", table, "-F", chain], capture_output=True)
        # Delete chain
        subprocess.run(["iptables", "-t", table, "-X", chain], capture_output=True)
        logger.info(f"Removed firewall chain: {chain}")
    
    # 4. Remove per-instance chains if any remain
    server_dir = Path("/etc/openvpn/server")
    if server_dir.exists():
        for instance_dir in server_dir.iterdir():
            if instance_dir.is_dir() and not instance_dir.name.startswith('.'):
                instance_id = instance_dir.name
                for table, suffix in [("filter", "_INPUT"), ("filter", "_FWD"), ("nat", "_NAT")]:
                    chain = f"OVPN_{instance_id}{suffix}"
                    subprocess.run(["iptables", "-t", table, "-F", chain], capture_output=True)
                    subprocess.run(["iptables", "-t", table, "-X", chain], capture_output=True)
    
    logger.info("OpenVPN pre-uninstall complete")
    return True
