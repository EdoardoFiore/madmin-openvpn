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
    
    # Helper to remove references to a chain (jumps)
    def remove_jumps_to_chain(chain_to_remove):
        for table in ["filter", "nat"]:
            try:
                # Find rules jumping to this chain
                res = subprocess.run(
                    ["iptables", "-t", table, "-S"], 
                    capture_output=True, text=True
                )
                if res.returncode != 0: continue
                
                for line in res.stdout.split('\n'):
                    if f"-j {chain_to_remove}" in line:
                        # Convert rule to delete command (replace -A with -D)
                        parts = line.split()
                        if "-A" in parts:
                            idx = parts.index("-A")
                            parts[idx] = "-D"
                            subprocess.run(["iptables", "-t", table] + parts, capture_output=True)
            except Exception:
                pass

    # 2. Robust Chain Cleanup: Find ALL OVPN_* chains currently in memory
    for table in ["filter", "nat"]:
        try:
            result = subprocess.run(
                ["iptables", "-t", table, "-L", "-n"],
                capture_output=True, text=True
            )
            # Find all chains starting with OVPN_ or MOD_OVPN_
            chains_to_remove = []
            for line in result.stdout.split('\n'):
                if line.startswith("Chain OVPN_") or line.startswith("Chain MOD_OVPN_"):
                    chain_name = line.split()[1]
                    chains_to_remove.append(chain_name)
            
            # Sort to delete instance/group chains BEFORE module chains (dependencies)
            # Groups/Instances start with OVPN_, Module starts with MOD_OVPN_
            # We want to delete OVPN_* first, then MOD_OVPN_*
            # Actually, simply flushing everything first helps
            
            for chain in chains_to_remove:
                # 1. Remove references to this chain from other chains
                remove_jumps_to_chain(chain)
                # 2. Flush chain
                subprocess.run(["iptables", "-t", table, "-F", chain], capture_output=True)
            
            # 3. Delete chains (now empty and unreferenced)
            for chain in chains_to_remove:
                subprocess.run(["iptables", "-t", table, "-X", chain], capture_output=True)
                logger.info(f"Removed chain: {chain} ({table})")
                
        except Exception as e:
            logger.warning(f"Error cleaning up {table} table: {e}")
    
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
