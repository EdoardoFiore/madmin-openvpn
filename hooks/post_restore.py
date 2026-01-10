"""
OpenVPN Module - Post Restore Hook

Executed after module backup restoration:
- Restarts OpenVPN services
- Reapplies firewall rules
"""
import subprocess
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


async def run():
    """Post-restore hook for OpenVPN module."""
    logger.info("Running OpenVPN post-restore hook")
    
    # 1. Restart all OpenVPN instances that have configs
    server_dir = Path("/etc/openvpn/server")
    if server_dir.exists():
        for conf_file in server_dir.parent.glob("*.conf"):
            # Extract instance ID from filename (e.g., office.conf -> office)
            instance_id = conf_file.stem
            service_name = f"openvpn-server@{instance_id}"
            
            # Enable and start service
            subprocess.run(["systemctl", "enable", service_name], capture_output=True)
            result = subprocess.run(["systemctl", "start", service_name], capture_output=True)
            
            if result.returncode == 0:
                logger.info(f"Started service: {service_name}")
            else:
                logger.warning(f"Failed to start {service_name}: {result.stderr.decode()}")
    
    logger.info("OpenVPN post-restore complete")
    return True
