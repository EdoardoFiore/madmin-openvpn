"""
OpenVPN Module - Pre Uninstall Hook

Executed before module uninstallation:
- Stops all running instances
- Removes firewall chains (instance and group chains)
- Removes configuration and PKI directories
"""
import subprocess
import logging
import shutil
from pathlib import Path

logger = logging.getLogger(__name__)


async def run():
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
                subprocess.run(["systemctl", "disable", service], capture_output=True)
                logger.info(f"Stopped and disabled service: {service}")
    except Exception as e:
        logger.warning(f"Error stopping services: {e}")
    
    # 2. Remove group chains (OVPN_GRP_*) from filter table
    try:
        result = subprocess.run(
            ["iptables", "-t", "filter", "-L", "-n", "--line-numbers"],
            capture_output=True,
            text=True
        )
        # Find and delete group chains
        for line in result.stdout.split('\n'):
            if 'Chain OVPN_GRP_' in line:
                chain_name = line.split()[1]
                subprocess.run(["iptables", "-t", "filter", "-F", chain_name], capture_output=True)
                subprocess.run(["iptables", "-t", "filter", "-X", chain_name], capture_output=True)
                logger.info(f"Removed group chain: {chain_name}")
    except Exception as e:
        logger.warning(f"Error removing group chains: {e}")
    
    # 3. Remove per-instance chains (OVPN_{instance}_INPUT, _FWD, _NAT)
    server_dir = Path("/etc/openvpn/server")
    if server_dir.exists():
        for instance_dir in server_dir.iterdir():
            if instance_dir.is_dir() and not instance_dir.name.startswith('.'):
                instance_id = instance_dir.name
                # Filter table chains
                for suffix in ["_INPUT", "_FWD"]:
                    chain = f"OVPN_{instance_id}{suffix}"
                    subprocess.run(["iptables", "-t", "filter", "-F", chain], capture_output=True)
                    subprocess.run(["iptables", "-t", "filter", "-X", chain], capture_output=True)
                # NAT table chain
                for suffix in ["_NAT"]:
                    chain = f"OVPN_{instance_id}{suffix}"
                    subprocess.run(["iptables", "-t", "nat", "-F", chain], capture_output=True)
                    subprocess.run(["iptables", "-t", "nat", "-X", chain], capture_output=True)
                logger.info(f"Removed instance chains for: {instance_id}")
    
    # 4. Remove jump rules from parent module chains
    jump_rules = [
        ("filter", "MOD_OVPN_INPUT"),
        ("filter", "MOD_OVPN_FORWARD"),
        ("nat", "MOD_OVPN_NAT"),
    ]
    
    for table, chain in jump_rules:
        # Flush chain first
        subprocess.run(["iptables", "-t", table, "-F", chain], capture_output=True)
        # Delete chain
        subprocess.run(["iptables", "-t", table, "-X", chain], capture_output=True)
        logger.info(f"Removed module firewall chain: {chain}")
    
    # 5. Remove MADMIN -> module jump rules (the core will handle this, but clean up just in case)
    for table, parent, chain in [
        ("filter", "INPUT", "MOD_OVPN_INPUT"),
        ("filter", "FORWARD", "MOD_OVPN_FORWARD"),
        ("nat", "POSTROUTING", "MOD_OVPN_NAT"),
    ]:
        subprocess.run(["iptables", "-t", table, "-D", parent, "-j", chain], capture_output=True)
    
    # 6. Remove configuration and PKI directories
    dirs_to_remove = [
        Path("/etc/openvpn/server"),  # Instance configs, PKI, CCD
    ]
    
    for dir_path in dirs_to_remove:
        if dir_path.exists():
            try:
                shutil.rmtree(dir_path)
                logger.info(f"Removed directory: {dir_path}")
            except Exception as e:
                logger.warning(f"Failed to remove {dir_path}: {e}")
    
    # 7. Remove .conf files from /etc/openvpn/ (root level)
    openvpn_root = Path("/etc/openvpn")
    if openvpn_root.exists():
        for conf_file in openvpn_root.glob("*.conf"):
            try:
                conf_file.unlink()
                logger.info(f"Removed config file: {conf_file}")
            except Exception as e:
                logger.warning(f"Failed to remove {conf_file}: {e}")
    
    logger.info("OpenVPN pre-uninstall complete")
    return True
