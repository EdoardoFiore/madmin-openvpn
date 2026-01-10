"""
OpenVPN Module - Post Update Hook

Executed after module update:
- Restarts running instances to apply changes
"""
import subprocess
import logging

logger = logging.getLogger(__name__)


async def run():
    """Post-update hook for OpenVPN module."""
    logger.info("Running OpenVPN post-update hook")
    
    # Restart any running OpenVPN services
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
                subprocess.run(["systemctl", "restart", service], capture_output=True)
                logger.info(f"Restarted service: {service}")
    except Exception as e:
        logger.warning(f"Error restarting services: {e}")
    
    logger.info("OpenVPN post-update complete")
    return True
