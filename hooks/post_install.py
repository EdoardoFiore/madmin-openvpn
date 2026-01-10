"""
OpenVPN Module - Post Install Hook

Executed after module installation:
- Creates necessary directories
- Enables IP forwarding
"""
import subprocess
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


async def run():
    """Post-install hook for OpenVPN module."""
    logger.info("Running OpenVPN post-install hook")
    
    # 1. Create OpenVPN directories
    dirs = [
        Path("/etc/openvpn/server"),
        Path("/var/log/openvpn"),
    ]
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)
        logger.info(f"Created directory: {d}")
    
    # 2. Enable IP forwarding
    try:
        # Check current value
        with open("/proc/sys/net/ipv4/ip_forward") as f:
            if f.read().strip() != "1":
                # Enable temporarily
                with open("/proc/sys/net/ipv4/ip_forward", "w") as fw:
                    fw.write("1")
                logger.info("Enabled IPv4 forwarding")
        
        # Enable permanently
        sysctl_conf = Path("/etc/sysctl.d/99-openvpn.conf")
        sysctl_conf.write_text("net.ipv4.ip_forward = 1\n")
        subprocess.run(["sysctl", "-p", str(sysctl_conf)], capture_output=True)
        logger.info("IPv4 forwarding enabled permanently")
    except Exception as e:
        logger.warning(f"Could not enable IP forwarding: {e}")
    
    logger.info("OpenVPN post-install complete")
