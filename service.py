"""
OpenVPN Module - Service Layer

Business logic for OpenVPN operations: PKI management, config generation,
interface control, IP allocation, CCD management, and firewall rules.
"""
import subprocess
import logging
import re
import shutil
import urllib.request
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from datetime import datetime, timedelta
from ipaddress import IPv4Network
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from .models import OvpnInstance, OvpnClient

logger = logging.getLogger(__name__)

# Paths
OPENVPN_BASE_DIR = Path("/etc/openvpn/server")
EASYRSA_SOURCE = Path("/usr/share/easy-rsa")

# Cached public IP
_cached_public_ip = None


def get_public_ip() -> Optional[str]:
    """
    Get server's public IP address.
    Tries multiple services, caches result.
    """
    global _cached_public_ip
    if _cached_public_ip:
        return _cached_public_ip
    
    services = [
        "https://api.ipify.org",
        "https://icanhazip.com",
        "https://checkip.amazonaws.com",
        "https://ifconfig.me/ip"
    ]
    
    for url in services:
        try:
            with urllib.request.urlopen(url, timeout=5) as response:
                ip = response.read().decode('utf-8').strip()
                if ip:
                    _cached_public_ip = ip
                    logger.info(f"Detected public IP: {ip}")
                    return ip
        except Exception as e:
            logger.debug(f"Failed to get IP from {url}: {e}")
            continue
    
    logger.warning("Could not detect public IP from any service")
    return None


class OpenVPNService:
    """Service class for OpenVPN operations."""
    
    # Firewall chain names
    OVPN_INPUT_CHAIN = "MOD_OVPN_INPUT"
    OVPN_FORWARD_CHAIN = "MOD_OVPN_FORWARD"
    OVPN_NAT_CHAIN = "MOD_OVPN_NAT"
    
    # =========================================================================
    # PKI MANAGEMENT
    # =========================================================================
    
    @staticmethod
    def get_instance_dir(instance_id: str) -> Path:
        """Get the directory for an instance."""
        return OPENVPN_BASE_DIR / instance_id
    
    @staticmethod
    def get_easyrsa_dir(instance_id: str) -> Path:
        """Get the easy-rsa directory for an instance."""
        return OpenVPNService.get_instance_dir(instance_id) / "easy-rsa"
    
    @staticmethod
    def get_ccd_dir(instance_id: str) -> Path:
        """Get the CCD directory for an instance."""
        return OpenVPNService.get_instance_dir(instance_id) / "ccd"
    
    @staticmethod
    def init_pki(instance_id: str) -> bool:
        """Initialize PKI for a new instance."""
        instance_dir = OpenVPNService.get_instance_dir(instance_id)
        easyrsa_dir = OpenVPNService.get_easyrsa_dir(instance_id)
        ccd_dir = OpenVPNService.get_ccd_dir(instance_id)
        
        try:
            # Create directories
            instance_dir.mkdir(parents=True, exist_ok=True)
            ccd_dir.mkdir(parents=True, exist_ok=True)
            
            # Copy easy-rsa
            if easyrsa_dir.exists():
                shutil.rmtree(easyrsa_dir)
            shutil.copytree(EASYRSA_SOURCE, easyrsa_dir)
            
            # Initialize PKI
            subprocess.run(
                ["./easyrsa", "init-pki"],
                cwd=easyrsa_dir,
                check=True,
                capture_output=True
            )
            
            logger.info(f"PKI initialized for instance {instance_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to init PKI for {instance_id}: {e}")
            return False
    
    @staticmethod
    def build_ca(instance_id: str, cn: str = "MADMIN OpenVPN CA", days: int = 3650) -> Dict:
        """Build Certificate Authority."""
        easyrsa_dir = OpenVPNService.get_easyrsa_dir(instance_id)
        
        try:
            # Set environment for non-interactive
            env = {
                "EASYRSA_BATCH": "1",
                "EASYRSA_REQ_CN": cn,
                "EASYRSA_CA_EXPIRE": str(days),
            }
            
            subprocess.run(
                ["./easyrsa", "--batch", f"--days={days}", "build-ca", "nopass"],
                cwd=easyrsa_dir,
                env={**subprocess.os.environ, **env},
                check=True,
                capture_output=True
            )
            
            # Read CA cert
            ca_cert_path = easyrsa_dir / "pki" / "ca.crt"
            expiry = OpenVPNService._parse_cert_expiry(ca_cert_path)
            
            logger.info(f"CA built for instance {instance_id}")
            return {
                "success": True,
                "ca_cert": ca_cert_path.read_text(),
                "expiry": expiry
            }
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to build CA: {e.stderr.decode()}")
            return {"success": False, "error": str(e)}
    
    @staticmethod
    def generate_server_cert(instance_id: str, days: int = 3650) -> Dict:
        """Generate server certificate."""
        easyrsa_dir = OpenVPNService.get_easyrsa_dir(instance_id)
        server_name = f"server_{instance_id}"
        
        try:
            # Generate server keypair and cert
            subprocess.run(
                ["./easyrsa", "--batch", f"--days={days}", 
                 "build-server-full", server_name, "nopass"],
                cwd=easyrsa_dir,
                check=True,
                capture_output=True
            )
            
            # Read cert and key
            cert_path = easyrsa_dir / "pki" / "issued" / f"{server_name}.crt"
            key_path = easyrsa_dir / "pki" / "private" / f"{server_name}.key"
            
            # Copy to instance directory
            instance_dir = OpenVPNService.get_instance_dir(instance_id)
            shutil.copy(cert_path, instance_dir / "server.crt")
            shutil.copy(key_path, instance_dir / "server.key")
            shutil.copy(easyrsa_dir / "pki" / "ca.crt", instance_dir / "ca.crt")
            
            # Generate DH params (or use ECDH)
            # For modern setup, use ecdh-curve instead
            
            # Generate tls-crypt-v2 key
            tls_key_path = instance_dir / "tls-crypt-v2.key"
            subprocess.run(
                ["openvpn", "--genkey", "tls-crypt-v2-server", str(tls_key_path)],
                check=True,
                capture_output=True
            )
            
            expiry = OpenVPNService._parse_cert_expiry(cert_path)
            
            logger.info(f"Server certificate generated for {instance_id}")
            return {
                "success": True,
                "expiry": expiry
            }
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to generate server cert: {e}")
            return {"success": False, "error": str(e)}
    
    @staticmethod
    def generate_client_cert(instance_id: str, client_name: str, days: int = 3650) -> Dict:
        """Generate client certificate."""
        easyrsa_dir = OpenVPNService.get_easyrsa_dir(instance_id)
        
        try:
            subprocess.run(
                ["./easyrsa", "--batch", f"--days={days}",
                 "build-client-full", client_name, "nopass"],
                cwd=easyrsa_dir,
                check=True,
                capture_output=True
            )
            
            cert_path = easyrsa_dir / "pki" / "issued" / f"{client_name}.crt"
            key_path = easyrsa_dir / "pki" / "private" / f"{client_name}.key"
            
            expiry = OpenVPNService._parse_cert_expiry(cert_path)
            fingerprint = OpenVPNService._get_cert_fingerprint(cert_path)
            
            logger.info(f"Client certificate generated: {client_name}")
            return {
                "success": True,
                "cert": cert_path.read_text(),
                "key": key_path.read_text(),
                "expiry": expiry,
                "fingerprint": fingerprint
            }
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to generate client cert: {e}")
            return {"success": False, "error": str(e)}
    
    @staticmethod
    def revoke_client_cert(instance_id: str, client_name: str) -> bool:
        """Revoke a client certificate and regenerate CRL."""
        easyrsa_dir = OpenVPNService.get_easyrsa_dir(instance_id)
        
        try:
            # Revoke certificate
            subprocess.run(
                ["./easyrsa", "--batch", "revoke", client_name],
                cwd=easyrsa_dir,
                check=True,
                capture_output=True
            )
            
            # Regenerate CRL
            OpenVPNService.regenerate_crl(instance_id)
            
            # Remove cert files
            for ext in [".crt", ".key", ".req"]:
                cert_file = easyrsa_dir / "pki" / "issued" / f"{client_name}{ext}"
                if cert_file.exists():
                    cert_file.unlink()
                key_file = easyrsa_dir / "pki" / "private" / f"{client_name}{ext}"
                if key_file.exists():
                    key_file.unlink()
            
            logger.info(f"Client certificate revoked: {client_name}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to revoke cert: {e}")
            return False
    
    @staticmethod
    def regenerate_crl(instance_id: str) -> bool:
        """Regenerate Certificate Revocation List."""
        easyrsa_dir = OpenVPNService.get_easyrsa_dir(instance_id)
        instance_dir = OpenVPNService.get_instance_dir(instance_id)
        
        try:
            subprocess.run(
                ["./easyrsa", "gen-crl"],
                cwd=easyrsa_dir,
                check=True,
                capture_output=True
            )
            
            # Copy CRL to instance directory
            crl_src = easyrsa_dir / "pki" / "crl.pem"
            crl_dst = instance_dir / "crl.pem"
            shutil.copy(crl_src, crl_dst)
            crl_dst.chmod(0o644)
            
            logger.info(f"CRL regenerated for {instance_id}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to regenerate CRL: {e}")
            return False
    
    @staticmethod
    def renew_server_cert(instance_id: str, days: int = 3650) -> Dict:
        """Renew server certificate."""
        easyrsa_dir = OpenVPNService.get_easyrsa_dir(instance_id)
        server_name = f"server_{instance_id}"
        
        try:
            # Revoke old cert
            subprocess.run(
                ["./easyrsa", "--batch", "revoke", server_name],
                cwd=easyrsa_dir,
                capture_output=True
            )
            
            # Remove old files
            for subdir in ["issued", "private", "reqs"]:
                for ext in [".crt", ".key", ".req"]:
                    old_file = easyrsa_dir / "pki" / subdir / f"{server_name}{ext}"
                    if old_file.exists():
                        old_file.unlink()
            
            # Generate new certificate
            return OpenVPNService.generate_server_cert(instance_id, days)
        except Exception as e:
            logger.error(f"Failed to renew server cert: {e}")
            return {"success": False, "error": str(e)}
    
    @staticmethod
    def renew_client_cert(instance_id: str, client_name: str, days: int = 3650) -> Dict:
        """Renew client certificate (revoke old + generate new)."""
        easyrsa_dir = OpenVPNService.get_easyrsa_dir(instance_id)
        
        try:
            # Revoke old cert
            subprocess.run(
                ["./easyrsa", "--batch", "revoke", client_name],
                cwd=easyrsa_dir,
                capture_output=True
            )
            
            # Remove old files
            for subdir in ["issued", "private", "reqs"]:
                for ext in [".crt", ".key", ".req"]:
                    old_file = easyrsa_dir / "pki" / subdir / f"{client_name}{ext}"
                    if old_file.exists():
                        old_file.unlink()
            
            # Regenerate CRL
            OpenVPNService.regenerate_crl(instance_id)
            
            # Generate new certificate
            return OpenVPNService.generate_client_cert(instance_id, client_name, days)
        except Exception as e:
            logger.error(f"Failed to renew client cert: {e}")
            return {"success": False, "error": str(e)}
    
    @staticmethod
    def _parse_cert_expiry(cert_path: Path) -> Optional[datetime]:
        """Parse certificate expiry date."""
        try:
            result = subprocess.run(
                ["openssl", "x509", "-enddate", "-noout", "-in", str(cert_path)],
                capture_output=True,
                text=True
            )
            # Output: notAfter=Jan  7 12:00:00 2036 GMT
            match = re.search(r'notAfter=(.+)', result.stdout)
            if match:
                date_str = match.group(1).strip()
                return datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
        except Exception as e:
            logger.error(f"Failed to parse cert expiry: {e}")
        return None
    
    @staticmethod
    def _get_cert_fingerprint(cert_path: Path) -> Optional[str]:
        """Get SHA256 fingerprint of certificate."""
        try:
            result = subprocess.run(
                ["openssl", "x509", "-fingerprint", "-sha256", "-noout", "-in", str(cert_path)],
                capture_output=True,
                text=True
            )
            match = re.search(r'sha256 Fingerprint=(.+)', result.stdout, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        except Exception as e:
            logger.error(f"Failed to get fingerprint: {e}")
        return None
    
    @staticmethod
    def get_cert_days_remaining(expiry: datetime) -> int:
        """Calculate days remaining until expiry."""
        if not expiry:
            return -1
        delta = expiry - datetime.utcnow()
        return max(0, delta.days)
    
    # =========================================================================
    # CCD (Client-Config-Dir) MANAGEMENT
    # =========================================================================
    
    @staticmethod
    def create_ccd_file(instance_id: str, client_name: str, static_ip: str) -> bool:
        """Create CCD file for static IP assignment."""
        ccd_dir = OpenVPNService.get_ccd_dir(instance_id)
        ccd_file = ccd_dir / client_name
        
        try:
            # Extract IP without mask
            ip_only = static_ip.split('/')[0]
            
            # Write CCD file
            ccd_file.write_text(f"ifconfig-push {ip_only} 255.255.255.0\n")
            ccd_file.chmod(0o644)
            
            logger.info(f"CCD file created: {client_name} -> {ip_only}")
            return True
        except Exception as e:
            logger.error(f"Failed to create CCD file: {e}")
            return False
    
    @staticmethod
    def delete_ccd_file(instance_id: str, client_name: str) -> bool:
        """Delete CCD file for a client."""
        ccd_file = OpenVPNService.get_ccd_dir(instance_id) / client_name
        
        try:
            if ccd_file.exists():
                ccd_file.unlink()
                logger.info(f"CCD file deleted: {client_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete CCD file: {e}")
            return False
    
    # =========================================================================
    # CONFIG GENERATION
    # =========================================================================
    
    @staticmethod
    def create_server_config(instance: OvpnInstance) -> str:
        """Generate server configuration file."""
        instance_dir = OpenVPNService.get_instance_dir(instance.id)
        
        # Parse subnet
        network = IPv4Network(instance.subnet, strict=False)
        
        config_lines = [
            f"# OpenVPN Server Config - {instance.name}",
            f"# Generated by MADMIN",
            "",
            f"port {instance.port}",
            f"proto {instance.protocol}",
            f"dev {instance.interface}",
            "dev-type tun",
            "",
            f"ca {instance_dir}/ca.crt",
            f"cert {instance_dir}/server.crt",
            f"key {instance_dir}/server.key",
            f"crl-verify {instance_dir}/crl.pem",
            f"tls-crypt-v2 {instance_dir}/tls-crypt-v2.key",
            "dh none",  # Use ECDH instead of DH parameters
            "",
            f"server {network.network_address} {network.netmask}",
            f"topology subnet",
            "",
            f"client-config-dir {instance_dir}/ccd",
            "",
            "keepalive 10 120",
            "",
            f"cipher {instance.cipher}",
            f"auth {instance.auth}",
            f"tls-version-min {instance.tls_version_min}",
            "",
            "user nobody",
            "group nogroup",
            "",
            "persist-key",
            "persist-tun",
            "",
            f"status /var/log/openvpn/status_{instance.id}.log",
            f"log-append /var/log/openvpn/{instance.id}.log",
            "verb 3",
            "",
            "# Management interface for status queries",
            f"management 127.0.0.1 {7500 + hash(instance.id) % 100}",
        ]
        
        # DNS servers
        dns_servers = instance.dns_servers if instance.dns_servers else ["8.8.8.8", "1.1.1.1"]
        for dns in dns_servers:
            config_lines.append(f'push "dhcp-option DNS {dns}"')
        
        # Routing
        if instance.tunnel_mode == "full":
            config_lines.append('push "redirect-gateway def1 bypass-dhcp"')
        else:
            # Split tunnel - push specific routes
            for route in instance.routes:
                network_str = route.get('network', '')
                if network_str:
                    try:
                        net = IPv4Network(network_str, strict=False)
                        config_lines.append(f'push "route {net.network_address} {net.netmask}"')
                    except:
                        pass
        
        return "\n".join(config_lines)
    
    @staticmethod
    def generate_client_config(instance: OvpnInstance, client: OvpnClient, endpoint: str) -> str:
        """Generate unified client .ovpn configuration."""
        instance_dir = OpenVPNService.get_instance_dir(instance.id)
        easyrsa_dir = OpenVPNService.get_easyrsa_dir(instance.id)
        
        # Read certificates and keys
        ca_cert = (instance_dir / "ca.crt").read_text()
        client_cert_path = easyrsa_dir / "pki" / "issued" / f"{client.name}.crt"
        client_key_path = easyrsa_dir / "pki" / "private" / f"{client.name}.key"
        
        # Extract only the certificate part (between BEGIN and END)
        client_cert_full = client_cert_path.read_text()
        cert_match = re.search(r'(-----BEGIN CERTIFICATE-----.*-----END CERTIFICATE-----)', 
                               client_cert_full, re.DOTALL)
        client_cert = cert_match.group(1) if cert_match else client_cert_full
        
        client_key = client_key_path.read_text()
        
        config_lines = [
            "# OpenVPN Client Config",
            f"# Instance: {instance.name}",
            f"# Client: {client.name}",
            f"# Generated: {datetime.utcnow().isoformat()}",
            "",
            "client",
            "dev tun",
            f"proto {instance.protocol}",
            f"remote {endpoint} {instance.port}",
            "resolv-retry infinite",
            "nobind",
            "",
            "persist-key",
            "persist-tun",
            "",
            "remote-cert-tls server",
            f"cipher {instance.cipher}",
            f"auth {instance.auth}",
            "auth-nocache",
            f"tls-version-min {instance.tls_version_min}",
            "",
            "verb 3",
            "",
        ]
        
        # Add inline certificates
        config_lines.extend([
            "<ca>",
            ca_cert.strip(),
            "</ca>",
            "",
            "<cert>",
            client_cert.strip(),
            "</cert>",
            "",
            "<key>",
            client_key.strip(),
            "</key>",
            "",
        ])
        
        # Add tls-crypt-v2 client key
        tls_server_key = instance_dir / "tls-crypt-v2.key"
        if tls_server_key.exists():
            # Generate per-client tls-crypt-v2 key
            try:
                result = subprocess.run(
                    ["openvpn", "--tls-crypt-v2", str(tls_server_key),
                     "--genkey", "tls-crypt-v2-client", "/dev/stdout"],
                    capture_output=True,
                    text=True
                )
                if result.returncode == 0:
                    config_lines.extend([
                        "<tls-crypt-v2>",
                        result.stdout.strip(),
                        "</tls-crypt-v2>",
                    ])
            except Exception as e:
                logger.warning(f"Could not generate tls-crypt-v2 client key: {e}")
        
        return "\n".join(config_lines)
    
    # =========================================================================
    # INTERFACE CONTROL
    # =========================================================================
    
    @staticmethod
    def start_instance(instance_id: str) -> bool:
        """Start OpenVPN instance."""
        try:
            subprocess.run(
                ["systemctl", "start", f"openvpn-server@{instance_id}"],
                check=True,
                capture_output=True
            )
            logger.info(f"Started OpenVPN instance: {instance_id}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to start instance: {e}")
            return False
    
    @staticmethod
    def stop_instance(instance_id: str) -> bool:
        """Stop OpenVPN instance."""
        try:
            subprocess.run(
                ["systemctl", "stop", f"openvpn-server@{instance_id}"],
                check=True,
                capture_output=True
            )
            logger.info(f"Stopped OpenVPN instance: {instance_id}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to stop instance: {e}")
            return False
    
    @staticmethod
    def get_instance_status(instance_id: str) -> bool:
        """Check if instance is running."""
        try:
            result = subprocess.run(
                ["systemctl", "is-active", f"openvpn-server@{instance_id}"],
                capture_output=True,
                text=True
            )
            return result.stdout.strip() == "active"
        except:
            return False
    
    @staticmethod
    def get_connected_clients(instance_id: str) -> List[Dict]:
        """Get list of connected clients via status file."""
        status_file = Path(f"/var/log/openvpn/status_{instance_id}.log")
        connected = []
        
        if not status_file.exists():
            return connected
        
        try:
            content = status_file.read_text()
            # Parse status file format
            in_clients = False
            for line in content.split('\n'):
                if line.startswith('ROUTING TABLE'):
                    break
                if in_clients and ',' in line:
                    parts = line.split(',')
                    if len(parts) >= 5:
                        connected.append({
                            'common_name': parts[0],
                            'real_address': parts[1],
                            'bytes_received': int(parts[2]) if parts[2].isdigit() else 0,
                            'bytes_sent': int(parts[3]) if parts[3].isdigit() else 0,
                            'connected_since': parts[4],
                        })
                if line.startswith('Common Name'):
                    in_clients = True
        except Exception as e:
            logger.error(f"Failed to parse status file: {e}")
        
        return connected
    
    # =========================================================================
    # IP ALLOCATION
    # =========================================================================
    
    @staticmethod
    async def allocate_client_ip(session: AsyncSession, instance: OvpnInstance) -> str:
        """Allocate next available IP for client."""
        network = IPv4Network(instance.subnet, strict=False)
        
        # Get all allocated IPs
        result = await session.execute(
            select(OvpnClient.allocated_ip).where(
                OvpnClient.instance_id == instance.id
            )
        )
        used_ips = {row[0].split('/')[0] for row in result.all()}
        
        # Server uses .1
        used_ips.add(str(network.network_address + 1))
        
        # Find first available
        for i, ip in enumerate(network.hosts()):
            if i == 0:  # Skip .1 (server)
                continue
            if str(ip) not in used_ips:
                return f"{ip}/32"
        
        raise ValueError("No available IPs in subnet")
    
    # =========================================================================
    # FIREWALL MANAGEMENT
    # =========================================================================
    
    @staticmethod
    def _run_iptables(table: str, args: List[str], suppress_errors: bool = False) -> bool:
        """Execute an iptables command."""
        cmd = ["iptables"]
        if table != "filter":
            cmd.extend(["-t", table])
        cmd.extend(args)
        
        try:
            subprocess.run(cmd, check=True, capture_output=True)
            return True
        except subprocess.CalledProcessError as e:
            if not suppress_errors:
                logger.warning(f"iptables command failed: {' '.join(cmd)}: {e.stderr.decode()}")
            return False
    
    @staticmethod
    def _get_default_interface() -> str:
        """Detect the default network interface."""
        try:
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True,
                text=True
            )
            match = re.search(r'dev\s+(\S+)', result.stdout)
            if match:
                return match.group(1)
        except:
            pass
        return "eth0"
    
    @staticmethod
    def _create_or_flush_chain(chain_name: str, table: str = "filter") -> bool:
        """Create chain if doesn't exist, or flush it."""
        OpenVPNService._run_iptables(table, ["-N", chain_name], suppress_errors=True)
        return OpenVPNService._run_iptables(table, ["-F", chain_name])
    
    @staticmethod
    def _ensure_jump_rule(source_chain: str, target_chain: str, table: str = "filter") -> bool:
        """Ensure a jump rule exists from source to target chain.
        
        Inserts the jump BEFORE any RETURN rule to ensure proper ordering.
        """
        # Check if rule already exists
        result = subprocess.run(
            ["iptables", "-t", table, "-C", source_chain, "-j", target_chain],
            capture_output=True
        )
        if result.returncode == 0:
            return True  # Already exists
        
        # Find position of RETURN rule (if any) to insert before it
        result = subprocess.run(
            ["iptables", "-t", table, "-S", source_chain],
            capture_output=True,
            text=True
        )
        
        # Parse rules to find RETURN position
        lines = result.stdout.strip().split('\n') if result.returncode == 0 else []
        return_pos = None
        for i, line in enumerate(lines):
            if '-j RETURN' in line:
                return_pos = i
                break
        
        if return_pos is not None:
            # Insert before RETURN
            return OpenVPNService._run_iptables(table, ["-I", source_chain, str(return_pos), "-j", target_chain])
        else:
            # No RETURN, just append
            return OpenVPNService._run_iptables(table, ["-A", source_chain, "-j", target_chain])

    
    @staticmethod
    def _delete_chain(chain_name: str, table: str = "filter") -> bool:
        """Flush and delete a chain."""
        OpenVPNService._run_iptables(table, ["-F", chain_name], suppress_errors=True)
        return OpenVPNService._run_iptables(table, ["-X", chain_name], suppress_errors=True)
    
    @staticmethod
    def initialize_module_firewall_chains() -> bool:
        """Initialize module-level firewall chains."""
        OpenVPNService._create_or_flush_chain(OpenVPNService.OVPN_INPUT_CHAIN, "filter")
        OpenVPNService._create_or_flush_chain(OpenVPNService.OVPN_FORWARD_CHAIN, "filter")
        OpenVPNService._create_or_flush_chain(OpenVPNService.OVPN_NAT_CHAIN, "nat")
        
        # Add RETURN at end of chains
        OpenVPNService._run_iptables("filter", ["-A", OpenVPNService.OVPN_INPUT_CHAIN, "-j", "RETURN"])
        OpenVPNService._run_iptables("filter", ["-A", OpenVPNService.OVPN_FORWARD_CHAIN, "-j", "RETURN"])
        OpenVPNService._run_iptables("nat", ["-A", OpenVPNService.OVPN_NAT_CHAIN, "-j", "RETURN"])
        
        logger.info("OpenVPN module firewall chains initialized")
        return True
    
    @staticmethod
    def apply_instance_firewall_rules(
        instance_id: str,
        port: int,
        protocol: str,
        interface: str,
        subnet: str,
        tunnel_mode: str = "full",
        routes: list = None
    ) -> bool:
        """Apply firewall rules for an OpenVPN instance."""
        # Note: Module chains (MOD_OVPN_*) are created by core via manifest.json
        # We only create instance-specific chains here
        
        chain_id = instance_id.replace('tun', '') if instance_id.startswith('tun') else instance_id
        input_chain = f"OVPN_{chain_id}_INPUT"
        forward_chain = f"OVPN_{chain_id}_FWD"
        nat_chain = f"OVPN_{chain_id}_NAT"
        
        wan_interface = OpenVPNService._get_default_interface()
        
        logger.info(f"Applying firewall rules for OpenVPN instance {instance_id} (mode: {tunnel_mode})")
        
        # Create/flush instance chains
        OpenVPNService._create_or_flush_chain(input_chain, "filter")
        OpenVPNService._create_or_flush_chain(forward_chain, "filter")
        OpenVPNService._create_or_flush_chain(nat_chain, "nat")
        
        # INPUT rules
        OpenVPNService._run_iptables("filter", [
            "-A", input_chain, "-p", protocol, "--dport", str(port), "-j", "ACCEPT"
        ])
        OpenVPNService._run_iptables("filter", [
            "-A", input_chain, "-i", interface, "-j", "ACCEPT"
        ])
        OpenVPNService._run_iptables("filter", [
            "-A", input_chain, "-j", "RETURN"
        ])
        
        # FORWARD rules
        OpenVPNService._run_iptables("filter", [
            "-A", forward_chain, "-o", interface, "-j", "ACCEPT"
        ])
        
        if tunnel_mode == "split" and routes:
            for route in routes:
                network = route.get('network') if isinstance(route, dict) else route
                out_iface = route.get('interface') if isinstance(route, dict) and route.get('interface') else wan_interface
                if network:
                    OpenVPNService._run_iptables("filter", [
                        "-A", forward_chain, "-i", interface, "-d", network, "-j", "ACCEPT"
                    ])
            OpenVPNService._run_iptables("filter", [
                "-A", forward_chain, "-i", interface, "-d", subnet, "-j", "ACCEPT"
            ])
            OpenVPNService._run_iptables("filter", [
                "-A", forward_chain, "-i", interface, "-j", "DROP"
            ])
        else:
            OpenVPNService._run_iptables("filter", [
                "-A", forward_chain, "-i", interface, "-j", "ACCEPT"
            ])
        
        # NAT rules
        if tunnel_mode == "split" and routes:
            for route in routes:
                network = route.get('network') if isinstance(route, dict) else route
                out_iface = route.get('interface') if isinstance(route, dict) and route.get('interface') else wan_interface
                if network:
                    OpenVPNService._run_iptables("nat", [
                        "-A", nat_chain, "-s", subnet, "-d", network, "-o", out_iface, "-j", "MASQUERADE"
                    ])
        else:
            OpenVPNService._run_iptables("nat", [
                "-A", nat_chain, "-s", subnet, "-o", wan_interface, "-j", "MASQUERADE"
            ])
        
        OpenVPNService._run_iptables("nat", ["-A", nat_chain, "-j", "RETURN"])
        
        # Link to module chains
        OpenVPNService._ensure_jump_rule(OpenVPNService.OVPN_INPUT_CHAIN, input_chain, "filter")
        OpenVPNService._ensure_jump_rule(OpenVPNService.OVPN_FORWARD_CHAIN, forward_chain, "filter")
        OpenVPNService._ensure_jump_rule(OpenVPNService.OVPN_NAT_CHAIN, nat_chain, "nat")
        
        return True
    
    @staticmethod
    def remove_instance_firewall_rules(instance_id: str) -> bool:
        """Remove firewall rules for an instance."""
        chain_id = instance_id.replace('tun', '') if instance_id.startswith('tun') else instance_id
        input_chain = f"OVPN_{chain_id}_INPUT"
        forward_chain = f"OVPN_{chain_id}_FWD"
        nat_chain = f"OVPN_{chain_id}_NAT"
        
        # Remove jump rules
        OpenVPNService._run_iptables("filter", [
            "-D", OpenVPNService.OVPN_INPUT_CHAIN, "-j", input_chain
        ], suppress_errors=True)
        OpenVPNService._run_iptables("filter", [
            "-D", OpenVPNService.OVPN_FORWARD_CHAIN, "-j", forward_chain
        ], suppress_errors=True)
        OpenVPNService._run_iptables("nat", [
            "-D", OpenVPNService.OVPN_NAT_CHAIN, "-j", nat_chain
        ], suppress_errors=True)
        
        # Delete chains
        OpenVPNService._delete_chain(input_chain, "filter")
        OpenVPNService._delete_chain(forward_chain, "filter")
        OpenVPNService._delete_chain(nat_chain, "nat")
        
        logger.info(f"Firewall rules removed for instance {instance_id}")
        return True
    
    @staticmethod
    async def remove_all_group_chains(instance_id: str, db) -> bool:
        """
        Remove all group chains for an instance.
        Should be called before deleting an instance.
        """
        from .models import OvpnGroup
        
        logger.info(f"Removing group chains for instance {instance_id}")
        
        # Get all groups for this instance
        result = await db.execute(select(OvpnGroup).where(OvpnGroup.instance_id == instance_id))
        groups = result.scalars().all()
        
        for group in groups:
            group_chain = f"OVPN_GRP_{group.id.replace(instance_id + '_', '')}"
            OpenVPNService._delete_chain(group_chain, "filter")
            logger.info(f"  Deleted chain: {group_chain}")
        
        return True
    
    @staticmethod
    async def apply_group_firewall_rules(instance_id: str, db) -> bool:
        """
        Apply firewall rules for all groups in an instance.
        
        Chain hierarchy:
        OVPN_{instance}_FWD → OVPN_GRP_{group_id} → rules → default policy
        
        For each group member, traffic from their IP is matched and jumped
        to the group's chain where rules are applied.
        """
        from .models import OvpnInstance, OvpnGroup, OvpnGroupMember, OvpnGroupRule, OvpnClient
        
        logger.info(f"Applying group firewall rules for instance {instance_id}")
        
        # Get instance
        result = await db.execute(select(OvpnInstance).where(OvpnInstance.id == instance_id))
        instance = result.scalar_one_or_none()
        if not instance:
            logger.error(f"Instance {instance_id} not found")
            return False
        
        # Instance forward chain name
        chain_id = instance_id.replace('tun', '') if instance_id.startswith('tun') else instance_id
        instance_fwd_chain = f"OVPN_{chain_id}_FWD"
        
        # Get all groups for this instance
        result = await db.execute(select(OvpnGroup).where(OvpnGroup.instance_id == instance_id))
        groups = result.scalars().all()
        
        for group in groups:
            group_chain = f"OVPN_GRP_{group.id.replace(instance_id + '_', '')}"
            
            # Create group chain
            OpenVPNService._create_or_flush_chain(group_chain, "filter")
            
            # Get rules for this group (ordered)
            result = await db.execute(
                select(OvpnGroupRule)
                .where(OvpnGroupRule.group_id == group.id)
                .order_by(OvpnGroupRule.order)
            )
            rules = result.scalars().all()
            
            # Add rules to group chain
            for rule in rules:
                args = ["-A", group_chain]
                
                # Protocol
                if rule.protocol and rule.protocol != "all":
                    args.extend(["-p", rule.protocol])
                
                # Destination
                if rule.destination and rule.destination != "0.0.0.0/0":
                    args.extend(["-d", rule.destination])
                
                # Port (only for tcp/udp)
                if rule.port and rule.protocol in ("tcp", "udp"):
                    args.extend(["--dport", rule.port])
                
                # Action
                args.extend(["-j", rule.action])
                
                OpenVPNService._run_iptables("filter", args)
            
            # Group chain ends with RETURN - default policy is at instance level
            OpenVPNService._run_iptables("filter", [
                "-A", group_chain, "-j", "RETURN"
            ])
            
            # Get members of this group
            result = await db.execute(
                select(OvpnGroupMember, OvpnClient)
                .join(OvpnClient, OvpnGroupMember.client_id == OvpnClient.id)
                .where(OvpnGroupMember.group_id == group.id)
            )
            members = result.all()
            
            # For each member, add a jump rule from instance chain to group chain
            for member, client in members:
                client_ip = client.allocated_ip.split('/')[0]  # Remove /32
                
                # Add jump rule matching source IP at beginning of instance chain
                # First remove any existing rule for this IP
                OpenVPNService._run_iptables("filter", [
                    "-D", instance_fwd_chain, "-s", client_ip, "-j", group_chain
                ], suppress_errors=True)
                
                # Insert at position 1 (before the default ACCEPT rules)
                OpenVPNService._run_iptables("filter", [
                    "-I", instance_fwd_chain, "1", "-s", client_ip, "-j", group_chain
                ])
                
                logger.info(f"  Added rule: {client_ip} -> {group_chain}")
        
        # After processing all groups, update the instance forward chain to use the default policy
        # Remove old generic rules (they'll be at the end)
        OpenVPNService._run_iptables("filter", [
            "-D", instance_fwd_chain, "-j", "ACCEPT"
        ], suppress_errors=True)
        OpenVPNService._run_iptables("filter", [
            "-D", instance_fwd_chain, "-j", "RETURN"
        ], suppress_errors=True)
        OpenVPNService._run_iptables("filter", [
            "-D", instance_fwd_chain, "-j", "DROP"
        ], suppress_errors=True)
        
        # Add the instance default policy at the end (for non-grouped clients)
        OpenVPNService._run_iptables("filter", [
            "-A", instance_fwd_chain, "-j", instance.firewall_default_policy
        ])
        
        logger.info(f"Group firewall rules applied for instance {instance_id}")
        logger.info(f"  Default policy for non-grouped clients: {instance.firewall_default_policy}")
        return True
    
    @staticmethod
    async def remove_group_firewall_rules(instance_id: str, group_id: str, group_name: str, db) -> bool:
        """Remove firewall rules for a specific group."""
        from .models import OvpnGroupMember, OvpnClient
        
        # Instance forward chain name
        chain_id = instance_id.replace('tun', '') if instance_id.startswith('tun') else instance_id
        instance_fwd_chain = f"OVPN_{chain_id}_FWD"
        group_chain = f"OVPN_GRP_{group_name}"
        
        logger.info(f"Removing firewall rules for group {group_name} (chain: {group_chain})")
        
        # Get members to remove their jump rules
        result = await db.execute(
            select(OvpnGroupMember, OvpnClient)
            .join(OvpnClient, OvpnGroupMember.client_id == OvpnClient.id)
            .where(OvpnGroupMember.group_id == group_id)
        )
        members = result.all()
        
        for member, client in members:
            client_ip = client.allocated_ip.split('/')[0] + "/32"
            logger.info(f"  Removing jump rule: {client_ip} -> {group_chain}")
            OpenVPNService._run_iptables("filter", [
                "-D", instance_fwd_chain, "-s", client_ip, "-j", group_chain
            ], suppress_errors=True)
        
        # Delete group chain
        logger.info(f"  Deleting chain: {group_chain}")
        OpenVPNService._delete_chain(group_chain, "filter")
        
        return True


# Module instance
openvpn_service = OpenVPNService()

