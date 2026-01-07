"""
OpenVPN Module - Post Install Hook

Executed after module installation:
- Creates necessary directories
- Initializes firewall chains
- Enables IP forwarding
- Creates log directory
"""
import subprocess
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def run():
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
    
    # 3. Initialize firewall chains
    chains = [
        ("filter", "MOD_OVPN_INPUT"),
        ("filter", "MOD_OVPN_FORWARD"),
        ("nat", "MOD_OVPN_NAT"),
    ]
    
    for table, chain in chains:
        # Create chain if not exists
        subprocess.run(
            ["iptables", "-t", table, "-N", chain],
            capture_output=True
        )
        # Add RETURN at end
        subprocess.run(
            ["iptables", "-t", table, "-A", chain, "-j", "RETURN"],
            capture_output=True
        )
        logger.info(f"Created firewall chain: {chain}")
    
    # 4. Create symlinks to module chains from MADMIN chains
    # This depends on core MADMIN chains existing
    jump_rules = [
        ("filter", "MADMIN_INPUT", "MOD_OVPN_INPUT"),
        ("filter", "MADMIN_FORWARD", "MOD_OVPN_FORWARD"),
        ("nat", "MADMIN_POSTROUTING", "MOD_OVPN_NAT"),
    ]
    
    for table, parent, chain in jump_rules:
        # Check if rule exists
        result = subprocess.run(
            ["iptables", "-t", table, "-C", parent, "-j", chain],
            capture_output=True
        )
        if result.returncode != 0:
            # Add jump rule
            subprocess.run(
                ["iptables", "-t", table, "-A", parent, "-j", chain],
                capture_output=True
            )
            logger.info(f"Added jump rule: {parent} -> {chain}")
    
    logger.info("OpenVPN post-install complete")
    return True
