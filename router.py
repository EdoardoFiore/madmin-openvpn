"""
OpenVPN Module - API Router

FastAPI endpoints for OpenVPN server management.
"""
import logging
import io
import re
from datetime import datetime, timedelta
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.responses import HTMLResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
import secrets
import qrcode

from backend.core.database import get_session
from backend.core.auth.dependencies import require_permission
from backend.core.auth.models import User

from .models import (
    OvpnInstance, OvpnInstanceCreate, OvpnInstanceRead,
    OvpnClient, OvpnClientCreate, OvpnClientRead,
    OvpnGroup, OvpnGroupCreate, OvpnGroupRead,
    OvpnGroupMember, OvpnGroupMemberRead,
    OvpnGroupRule, OvpnGroupRuleCreate, OvpnGroupRuleRead, OvpnGroupRuleUpdate,
    RuleOrderUpdate, FirewallPolicyUpdate, OvpnRoutingUpdate,
    OvpnMagicToken, SendConfigRequest, PKIStatusRead, CertRenewRequest
)
from .service import openvpn_service, OPENVPN_BASE_DIR

logger = logging.getLogger(__name__)
router = APIRouter()


# =========================================================================
# INSTANCES
# =========================================================================

@router.get("/instances", response_model=List[OvpnInstanceRead])
async def list_instances(
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("openvpn.view"))
):
    """List all OpenVPN instances."""
    result = await db.execute(select(OvpnInstance))
    instances = result.scalars().all()
    
    response = []
    for inst in instances:
        # Get client count
        count_result = await db.execute(
            select(func.count()).select_from(OvpnClient).where(
                (OvpnClient.instance_id == inst.id) & (OvpnClient.revoked == False)
            )
        )
        client_count = count_result.scalar() or 0
        
        # Check real status
        is_running = openvpn_service.get_instance_status(inst.id)
        
        response.append(OvpnInstanceRead(
            **inst.model_dump(),
            status="running" if is_running else "stopped",
            client_count=client_count
        ))
    
    return response


@router.post("/instances", response_model=OvpnInstanceRead, status_code=201)
async def create_instance(
    data: OvpnInstanceCreate,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("openvpn.manage"))
):
    """Create new OpenVPN instance with PKI."""
    # Generate instance ID from name
    instance_id = re.sub(r'[^a-z0-9]', '', data.name.lower())[:20]
    
    # Check if exists
    existing = await db.execute(
        select(OvpnInstance).where(OvpnInstance.id == instance_id)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(400, "Instance with this name already exists")
    
    # Check port
    port_check = await db.execute(
        select(OvpnInstance).where(OvpnInstance.port == data.port)
    )
    if port_check.scalar_one_or_none():
        raise HTTPException(400, f"Port {data.port} already in use")
    
    # Generate interface name
    interface = f"tun{data.port % 100}"
    
    # Initialize PKI
    if not openvpn_service.init_pki(instance_id):
        raise HTTPException(500, "Failed to initialize PKI")
    
    # Build CA
    ca_result = openvpn_service.build_ca(instance_id, f"{data.name} CA", data.cert_duration_days)
    if not ca_result.get("success"):
        raise HTTPException(500, f"Failed to build CA: {ca_result.get('error')}")
    
    # Generate server certificate
    server_result = openvpn_service.generate_server_cert(instance_id, data.cert_duration_days)
    if not server_result.get("success"):
        raise HTTPException(500, f"Failed to generate server cert: {server_result.get('error')}")
    
    # Create instance record
    instance = OvpnInstance(
        id=instance_id,
        name=data.name,
        port=data.port,
        protocol=data.protocol,
        subnet=data.subnet,
        interface=interface,
        tunnel_mode=data.tunnel_mode,
        routes=data.routes,
        dns_servers=data.dns_servers,
        cipher=data.cipher,
        cert_duration_days=data.cert_duration_days,
        endpoint=data.endpoint,
        ca_cert_expiry=ca_result.get("expiry"),
        server_cert_expiry=server_result.get("expiry"),
        status="stopped"
    )
    db.add(instance)
    
    # Generate server config
    config = openvpn_service.create_server_config(instance)
    config_path = OPENVPN_BASE_DIR / instance_id / f"{instance_id}.conf"
    config_path.write_text(config)
    config_path.chmod(0o600)
    
    # Create symlink for systemd
    systemd_config = OPENVPN_BASE_DIR / f"{instance_id}.conf"
    if not systemd_config.exists():
        systemd_config.symlink_to(config_path)
    
    # Generate initial CRL
    openvpn_service.regenerate_crl(instance_id)
    
    await db.commit()
    
    return OvpnInstanceRead(
        **instance.model_dump(),
        status="stopped",
        client_count=0
    )


@router.get("/instances/{instance_id}", response_model=OvpnInstanceRead)
async def get_instance(
    instance_id: str,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("openvpn.view"))
):
    """Get a single OpenVPN instance by ID."""
    result = await db.execute(select(OvpnInstance).where(OvpnInstance.id == instance_id))
    instance = result.scalar_one_or_none()
    if not instance:
        raise HTTPException(404, "Instance not found")
    
    # Get client count
    count_result = await db.execute(
        select(func.count()).select_from(OvpnClient).where(
            (OvpnClient.instance_id == instance_id) & (OvpnClient.revoked == False)
        )
    )
    client_count = count_result.scalar() or 0
    
    is_running = openvpn_service.get_instance_status(instance_id)
    
    return OvpnInstanceRead(
        **instance.model_dump(),
        status="running" if is_running else "stopped",
        client_count=client_count
    )


@router.delete("/instances/{instance_id}", status_code=204)
async def delete_instance(
    instance_id: str,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("openvpn.manage"))
):
    """Delete OpenVPN instance."""
    result = await db.execute(select(OvpnInstance).where(OvpnInstance.id == instance_id))
    instance = result.scalar_one_or_none()
    if not instance:
        raise HTTPException(404, "Instance not found")
    
    # Stop instance
    openvpn_service.stop_instance(instance_id)
    
    # Remove firewall rules
    openvpn_service.remove_instance_firewall_rules(instance_id)
    
    # Delete from database
    await db.delete(instance)
    await db.commit()
    
    # Note: PKI files remain on disk for potential backup/recovery


@router.post("/instances/{instance_id}/start")
async def start_instance(
    instance_id: str,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("openvpn.manage"))
):
    """Start OpenVPN instance."""
    result = await db.execute(select(OvpnInstance).where(OvpnInstance.id == instance_id))
    instance = result.scalar_one_or_none()
    if not instance:
        raise HTTPException(404, "Instance not found")
    
    if openvpn_service.start_instance(instance_id):
        # Apply firewall rules
        openvpn_service.apply_instance_firewall_rules(
            instance_id, instance.port, instance.protocol,
            instance.interface, instance.subnet,
            instance.tunnel_mode, instance.routes
        )
        return {"status": "running"}
    raise HTTPException(500, "Failed to start instance")


@router.post("/instances/{instance_id}/stop")
async def stop_instance(
    instance_id: str,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("openvpn.manage"))
):
    """Stop OpenVPN instance."""
    result = await db.execute(select(OvpnInstance).where(OvpnInstance.id == instance_id))
    instance = result.scalar_one_or_none()
    if not instance:
        raise HTTPException(404, "Instance not found")
    
    if openvpn_service.stop_instance(instance_id):
        openvpn_service.remove_instance_firewall_rules(instance_id)
        return {"status": "stopped"}
    raise HTTPException(500, "Failed to stop instance")


@router.patch("/instances/{instance_id}/routing")
async def update_instance_routing(
    instance_id: str,
    data: OvpnRoutingUpdate,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("openvpn.manage"))
):
    """Update routing mode for an instance."""
    result = await db.execute(select(OvpnInstance).where(OvpnInstance.id == instance_id))
    instance = result.scalar_one_or_none()
    if not instance:
        raise HTTPException(404, "Instance not found")
    
    if data.tunnel_mode not in ["full", "split"]:
        raise HTTPException(400, "Invalid tunnel mode")
    
    if data.tunnel_mode == "split" and not data.routes:
        raise HTTPException(400, "Split tunnel requires at least one route")
    
    # Update instance
    instance.tunnel_mode = data.tunnel_mode
    instance.routes = data.routes
    if data.dns_servers:
        instance.dns_servers = data.dns_servers
    instance.updated_at = datetime.utcnow()
    
    await db.commit()
    await db.refresh(instance)
    
    # Regenerate config
    config = openvpn_service.create_server_config(instance)
    config_path = OPENVPN_BASE_DIR / instance_id / f"{instance_id}.conf"
    config_path.write_text(config)
    
    # Reapply firewall if running
    if openvpn_service.get_instance_status(instance_id):
        openvpn_service.apply_instance_firewall_rules(
            instance_id, instance.port, instance.protocol,
            instance.interface, instance.subnet,
            instance.tunnel_mode, instance.routes
        )
    
    # Count affected clients
    count_result = await db.execute(
        select(func.count()).select_from(OvpnClient).where(
            (OvpnClient.instance_id == instance_id) & (OvpnClient.revoked == False)
        )
    )
    client_count = count_result.scalar() or 0
    
    return {
        "success": True,
        "message": "Routing mode updated",
        "tunnel_mode": instance.tunnel_mode,
        "routes": instance.routes,
        "warning": f"{client_count} clients need to re-download configuration" if client_count > 0 else None
    }


# =========================================================================
# PKI
# =========================================================================

@router.get("/instances/{instance_id}/pki/status", response_model=PKIStatusRead)
async def get_pki_status(
    instance_id: str,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("openvpn.view"))
):
    """Get PKI status for an instance."""
    result = await db.execute(select(OvpnInstance).where(OvpnInstance.id == instance_id))
    instance = result.scalar_one_or_none()
    if not instance:
        raise HTTPException(404, "Instance not found")
    
    # Count revoked clients
    revoked_result = await db.execute(
        select(func.count()).select_from(OvpnClient).where(
            (OvpnClient.instance_id == instance_id) & (OvpnClient.revoked == True)
        )
    )
    revoked_count = revoked_result.scalar() or 0
    
    return PKIStatusRead(
        ca_expiry=instance.ca_cert_expiry,
        ca_days_remaining=openvpn_service.get_cert_days_remaining(instance.ca_cert_expiry) if instance.ca_cert_expiry else None,
        server_cert_expiry=instance.server_cert_expiry,
        server_cert_days_remaining=openvpn_service.get_cert_days_remaining(instance.server_cert_expiry) if instance.server_cert_expiry else None,
        revoked_clients_count=revoked_count
    )


@router.post("/instances/{instance_id}/pki/renew-server")
async def renew_server_cert(
    instance_id: str,
    data: CertRenewRequest = None,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("openvpn.manage"))
):
    """Renew server certificate."""
    result = await db.execute(select(OvpnInstance).where(OvpnInstance.id == instance_id))
    instance = result.scalar_one_or_none()
    if not instance:
        raise HTTPException(404, "Instance not found")
    
    days = data.duration_days if data and data.duration_days else instance.cert_duration_days
    
    renew_result = openvpn_service.renew_server_cert(instance_id, days)
    if not renew_result.get("success"):
        raise HTTPException(500, f"Failed to renew certificate: {renew_result.get('error')}")
    
    # Update instance
    instance.server_cert_expiry = renew_result.get("expiry")
    instance.updated_at = datetime.utcnow()
    await db.commit()
    
    # Restart instance if running
    was_running = openvpn_service.get_instance_status(instance_id)
    if was_running:
        openvpn_service.stop_instance(instance_id)
        openvpn_service.start_instance(instance_id)
    
    return {
        "success": True,
        "message": "Server certificate renewed",
        "new_expiry": renew_result.get("expiry"),
        "restarted": was_running
    }


# =========================================================================
# CLIENTS
# =========================================================================

@router.get("/instances/{instance_id}/clients", response_model=List[OvpnClientRead])
async def list_clients(
    instance_id: str,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("openvpn.view"))
):
    """List clients for an instance with connection status."""
    result = await db.execute(
        select(OvpnClient).where(OvpnClient.instance_id == instance_id)
    )
    clients = result.scalars().all()
    
    # Get connected clients
    connected = openvpn_service.get_connected_clients(instance_id)
    connected_map = {c['common_name']: c for c in connected}
    
    response = []
    for client in clients:
        conn_info = connected_map.get(client.name, {})
        
        response.append(OvpnClientRead(
            id=client.id,
            name=client.name,
            allocated_ip=client.allocated_ip,
            cert_expiry=client.cert_expiry,
            cert_days_remaining=openvpn_service.get_cert_days_remaining(client.cert_expiry) if client.cert_expiry else None,
            revoked=client.revoked,
            created_at=client.created_at,
            last_connection=client.last_connection,
            is_connected=bool(conn_info),
            bytes_received=conn_info.get('bytes_received'),
            bytes_sent=conn_info.get('bytes_sent'),
        ))
    
    return response


@router.post("/instances/{instance_id}/clients", response_model=OvpnClientRead, status_code=201)
async def create_client(
    instance_id: str,
    data: OvpnClientCreate,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("openvpn.clients"))
):
    """Create new client with certificate."""
    result = await db.execute(select(OvpnInstance).where(OvpnInstance.id == instance_id))
    instance = result.scalar_one_or_none()
    if not instance:
        raise HTTPException(404, "Instance not found")
    
    # Validate name
    if not re.match(r'^[a-zA-Z0-9_-]+$', data.name):
        raise HTTPException(400, "Invalid client name")
    
    # Check if exists
    existing = await db.execute(
        select(OvpnClient).where(
            (OvpnClient.instance_id == instance_id) & 
            (OvpnClient.name == data.name)
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(400, "Client with this name already exists")
    
    # Allocate IP
    allocated_ip = await openvpn_service.allocate_client_ip(db, instance)
    
    # Generate certificate
    days = data.cert_duration_days if data.cert_duration_days else instance.cert_duration_days
    cert_result = openvpn_service.generate_client_cert(instance_id, data.name, days)
    if not cert_result.get("success"):
        raise HTTPException(500, f"Failed to generate certificate: {cert_result.get('error')}")
    
    # Create CCD file for static IP
    openvpn_service.create_ccd_file(instance_id, data.name, allocated_ip)
    
    # Create client record
    client = OvpnClient(
        instance_id=instance_id,
        name=data.name,
        allocated_ip=allocated_ip,
        cert_expiry=cert_result.get("expiry"),
        cert_fingerprint=cert_result.get("fingerprint"),
    )
    db.add(client)
    await db.commit()
    await db.refresh(client)
    
    return OvpnClientRead(
        id=client.id,
        name=client.name,
        allocated_ip=client.allocated_ip,
        cert_expiry=client.cert_expiry,
        cert_days_remaining=openvpn_service.get_cert_days_remaining(client.cert_expiry),
        revoked=False,
        created_at=client.created_at,
        last_connection=None,
        is_connected=False
    )


@router.delete("/instances/{instance_id}/clients/{client_name}", status_code=204)
async def revoke_client(
    instance_id: str,
    client_name: str,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("openvpn.clients"))
):
    """Revoke client certificate."""
    result = await db.execute(
        select(OvpnClient).where(
            (OvpnClient.instance_id == instance_id) &
            (OvpnClient.name == client_name)
        )
    )
    client = result.scalar_one_or_none()
    if not client:
        raise HTTPException(404, "Client not found")
    
    # Revoke certificate
    openvpn_service.revoke_client_cert(instance_id, client_name)
    
    # Delete CCD file
    openvpn_service.delete_ccd_file(instance_id, client_name)
    
    # Mark as revoked
    client.revoked = True
    client.revoked_at = datetime.utcnow()
    await db.commit()


@router.get("/instances/{instance_id}/clients/{client_name}/config")
async def get_client_config(
    instance_id: str,
    client_name: str,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("openvpn.clients"))
):
    """Download client .ovpn configuration."""
    # Get instance
    inst_result = await db.execute(select(OvpnInstance).where(OvpnInstance.id == instance_id))
    instance = inst_result.scalar_one_or_none()
    if not instance:
        raise HTTPException(404, "Instance not found")
    
    # Get client
    client_result = await db.execute(
        select(OvpnClient).where(
            (OvpnClient.instance_id == instance_id) &
            (OvpnClient.name == client_name) &
            (OvpnClient.revoked == False)
        )
    )
    client = client_result.scalar_one_or_none()
    if not client:
        raise HTTPException(404, "Client not found or revoked")
    
    # Determine endpoint
    endpoint = instance.endpoint
    if not endpoint:
        # Try to detect public IP
        import urllib.request
        try:
            endpoint = urllib.request.urlopen('https://api.ipify.org', timeout=5).read().decode()
        except:
            endpoint = "YOUR_SERVER_IP"
    
    config = openvpn_service.generate_client_config(instance, client, endpoint)
    
    return Response(
        content=config,
        media_type="application/x-openvpn-profile",
        headers={"Content-Disposition": f"attachment; filename={client_name}.ovpn"}
    )


@router.get("/instances/{instance_id}/clients/{client_name}/qr")
async def get_client_qr(
    instance_id: str,
    client_name: str,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("openvpn.clients"))
):
    """Get QR code for client config (limited use - config may be too large)."""
    # Note: OpenVPN configs are typically too large for QR codes
    # This provides a magic link QR instead
    
    # Get client
    client_result = await db.execute(
        select(OvpnClient).where(
            (OvpnClient.instance_id == instance_id) &
            (OvpnClient.name == client_name) &
            (OvpnClient.revoked == False)
        )
    )
    client = client_result.scalar_one_or_none()
    if not client:
        raise HTTPException(404, "Client not found or revoked")
    
    # Create magic token
    token = secrets.token_urlsafe(32)
    magic = OvpnMagicToken(
        token=token,
        client_id=client.id,
        expires_at=datetime.utcnow() + timedelta(hours=48)
    )
    db.add(magic)
    await db.commit()
    
    # Generate QR with download URL
    # Get base URL from request if possible, otherwise use placeholder
    download_url = f"/api/modules/openvpn/download/{token}"
    
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(download_url)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)
    
    return Response(content=buffer.getvalue(), media_type="image/png")


@router.post("/instances/{instance_id}/clients/{client_name}/renew")
async def renew_client_cert(
    instance_id: str,
    client_name: str,
    data: CertRenewRequest = None,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("openvpn.clients"))
):
    """Renew client certificate."""
    # Get instance
    inst_result = await db.execute(select(OvpnInstance).where(OvpnInstance.id == instance_id))
    instance = inst_result.scalar_one_or_none()
    if not instance:
        raise HTTPException(404, "Instance not found")
    
    # Get client
    client_result = await db.execute(
        select(OvpnClient).where(
            (OvpnClient.instance_id == instance_id) &
            (OvpnClient.name == client_name)
        )
    )
    client = client_result.scalar_one_or_none()
    if not client:
        raise HTTPException(404, "Client not found")
    
    days = data.duration_days if data and data.duration_days else instance.cert_duration_days
    
    renew_result = openvpn_service.renew_client_cert(instance_id, client_name, days)
    if not renew_result.get("success"):
        raise HTTPException(500, f"Failed to renew certificate: {renew_result.get('error')}")
    
    # Update client
    client.cert_expiry = renew_result.get("expiry")
    client.cert_fingerprint = renew_result.get("fingerprint")
    client.revoked = False
    client.revoked_at = None
    await db.commit()
    
    return {
        "success": True,
        "message": "Client certificate renewed",
        "new_expiry": renew_result.get("expiry"),
        "note": "Client must re-download configuration"
    }


# =========================================================================
# GROUPS
# =========================================================================

@router.get("/instances/{instance_id}/groups", response_model=List[OvpnGroupRead])
async def list_groups(
    instance_id: str,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("openvpn.view"))
):
    """List firewall groups for an instance."""
    result = await db.execute(
        select(OvpnGroup).where(OvpnGroup.instance_id == instance_id)
    )
    groups = result.scalars().all()
    
    response = []
    for group in groups:
        # Count members
        member_result = await db.execute(
            select(func.count()).select_from(OvpnGroupMember).where(
                OvpnGroupMember.group_id == group.id
            )
        )
        member_count = member_result.scalar() or 0
        
        # Count rules
        rule_result = await db.execute(
            select(func.count()).select_from(OvpnGroupRule).where(
                OvpnGroupRule.group_id == group.id
            )
        )
        rule_count = rule_result.scalar() or 0
        
        response.append(OvpnGroupRead(
            **group.model_dump(),
            member_count=member_count,
            rule_count=rule_count
        ))
    
    return response


@router.post("/instances/{instance_id}/groups", response_model=OvpnGroupRead, status_code=201)
async def create_group(
    instance_id: str,
    data: OvpnGroupCreate,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("openvpn.manage"))
):
    """Create a new firewall group."""
    # Verify instance exists
    inst_result = await db.execute(select(OvpnInstance).where(OvpnInstance.id == instance_id))
    if not inst_result.scalar_one_or_none():
        raise HTTPException(404, "Instance not found")
    
    # Generate group ID
    group_id = f"{instance_id}_{re.sub(r'[^a-z0-9]', '', data.name.lower())}"
    
    group = OvpnGroup(
        id=group_id,
        instance_id=instance_id,
        name=data.name,
        description=data.description
    )
    db.add(group)
    await db.commit()
    
    return OvpnGroupRead(**group.model_dump(), member_count=0, rule_count=0)


@router.delete("/instances/{instance_id}/groups/{group_id}", status_code=204)
async def delete_group(
    instance_id: str,
    group_id: str,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("openvpn.manage"))
):
    """Delete a firewall group."""
    result = await db.execute(
        select(OvpnGroup).where((OvpnGroup.id == group_id) & (OvpnGroup.instance_id == instance_id))
    )
    group = result.scalar_one_or_none()
    if not group:
        raise HTTPException(404, "Group not found")
    
    # TODO: Remove firewall rules for this group
    
    await db.delete(group)
    await db.commit()


# =========================================================================
# MEMBERS
# =========================================================================

@router.get("/instances/{instance_id}/groups/{group_id}/members", response_model=List[OvpnGroupMemberRead])
async def list_members(
    instance_id: str,
    group_id: str,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("openvpn.view"))
):
    """List members of a group."""
    result = await db.execute(
        select(OvpnGroupMember, OvpnClient)
        .join(OvpnClient, OvpnGroupMember.client_id == OvpnClient.id)
        .where(OvpnGroupMember.group_id == group_id)
    )
    return [
        OvpnGroupMemberRead(client_id=m.client_id, client_name=c.name, client_ip=c.allocated_ip)
        for m, c in result.all()
    ]


@router.post("/instances/{instance_id}/groups/{group_id}/members", status_code=201)
async def add_member(
    instance_id: str,
    group_id: str,
    client_id: str,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("openvpn.manage"))
):
    """Add a client to a group."""
    import uuid as uuid_mod
    
    # Verify group exists
    group_result = await db.execute(select(OvpnGroup).where(OvpnGroup.id == group_id))
    group = group_result.scalar_one_or_none()
    if not group:
        raise HTTPException(404, "Group not found")
    
    # Verify client exists
    client_result = await db.execute(
        select(OvpnClient).where(OvpnClient.id == uuid_mod.UUID(client_id))
    )
    client = client_result.scalar_one_or_none()
    if not client:
        raise HTTPException(404, "Client not found")
    
    # Check if already member
    existing = await db.execute(
        select(OvpnGroupMember).where(
            (OvpnGroupMember.group_id == group_id) &
            (OvpnGroupMember.client_id == uuid_mod.UUID(client_id))
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(400, "Client already in group")
    
    member = OvpnGroupMember(group_id=group_id, client_id=uuid_mod.UUID(client_id))
    db.add(member)
    await db.commit()
    
    # TODO: Apply firewall rule for this member
    
    return {"success": True}


@router.delete("/instances/{instance_id}/groups/{group_id}/members/{client_id}", status_code=204)
async def remove_member(
    instance_id: str,
    group_id: str,
    client_id: str,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("openvpn.manage"))
):
    """Remove a client from a group."""
    import uuid as uuid_mod
    
    result = await db.execute(
        select(OvpnGroupMember).where(
            (OvpnGroupMember.group_id == group_id) &
            (OvpnGroupMember.client_id == uuid_mod.UUID(client_id))
        )
    )
    member = result.scalar_one_or_none()
    if not member:
        raise HTTPException(404, "Member not found")
    
    # TODO: Remove firewall rule for this member
    
    await db.delete(member)
    await db.commit()


# =========================================================================
# RULES
# =========================================================================

@router.get("/instances/{instance_id}/groups/{group_id}/rules", response_model=List[OvpnGroupRuleRead])
async def list_rules(
    instance_id: str,
    group_id: str,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("openvpn.view"))
):
    """List rules for a group."""
    result = await db.execute(
        select(OvpnGroupRule)
        .where(OvpnGroupRule.group_id == group_id)
        .order_by(OvpnGroupRule.order)
    )
    return [OvpnGroupRuleRead(**r.model_dump()) for r in result.scalars().all()]


@router.post("/instances/{instance_id}/groups/{group_id}/rules", response_model=OvpnGroupRuleRead, status_code=201)
async def create_rule(
    instance_id: str,
    group_id: str,
    data: OvpnGroupRuleCreate,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("openvpn.manage"))
):
    """Create a new firewall rule."""
    # Verify group exists
    group_result = await db.execute(select(OvpnGroup).where(OvpnGroup.id == group_id))
    if not group_result.scalar_one_or_none():
        raise HTTPException(404, "Group not found")
    
    # Get max order
    max_order_result = await db.execute(
        select(func.max(OvpnGroupRule.order)).where(OvpnGroupRule.group_id == group_id)
    )
    max_order = max_order_result.scalar() or 0
    
    rule = OvpnGroupRule(
        group_id=group_id,
        action=data.action,
        protocol=data.protocol,
        port=data.port,
        destination=data.destination,
        description=data.description,
        order=max_order + 1
    )
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    
    # TODO: Apply firewall rule
    
    return OvpnGroupRuleRead(**rule.model_dump())


@router.patch("/instances/{instance_id}/groups/{group_id}/rules/{rule_id}", response_model=OvpnGroupRuleRead)
async def update_rule(
    instance_id: str,
    group_id: str,
    rule_id: str,
    data: OvpnGroupRuleUpdate,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("openvpn.manage"))
):
    """Update a firewall rule."""
    import uuid as uuid_mod
    
    result = await db.execute(
        select(OvpnGroupRule).where(OvpnGroupRule.id == uuid_mod.UUID(rule_id))
    )
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(404, "Rule not found")
    
    for key, value in data.model_dump(exclude_unset=True).items():
        if value is not None:
            setattr(rule, key, value)
    
    await db.commit()
    await db.refresh(rule)
    
    # TODO: Reapply firewall rules
    
    return OvpnGroupRuleRead(**rule.model_dump())


@router.delete("/instances/{instance_id}/groups/{group_id}/rules/{rule_id}", status_code=204)
async def delete_rule(
    instance_id: str,
    group_id: str,
    rule_id: str,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("openvpn.manage"))
):
    """Delete a firewall rule."""
    import uuid as uuid_mod
    
    result = await db.execute(
        select(OvpnGroupRule).where(OvpnGroupRule.id == uuid_mod.UUID(rule_id))
    )
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(404, "Rule not found")
    
    # TODO: Remove firewall rule
    
    await db.delete(rule)
    await db.commit()


@router.put("/instances/{instance_id}/groups/{group_id}/rules/order")
async def reorder_rules(
    instance_id: str,
    group_id: str,
    orders: List[RuleOrderUpdate],
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("openvpn.manage"))
):
    """Update rule order."""
    for order_update in orders:
        result = await db.execute(
            select(OvpnGroupRule).where(OvpnGroupRule.id == order_update.id)
        )
        rule = result.scalar_one_or_none()
        if rule:
            rule.order = order_update.order
    
    await db.commit()
    
    # TODO: Reapply firewall rules in new order
    
    return {"success": True}


# =========================================================================
# FIREWALL POLICY
# =========================================================================

@router.patch("/instances/{instance_id}/firewall/policy")
async def update_firewall_policy(
    instance_id: str,
    data: FirewallPolicyUpdate,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("openvpn.manage"))
):
    """Update instance default firewall policy."""
    result = await db.execute(select(OvpnInstance).where(OvpnInstance.id == instance_id))
    instance = result.scalar_one_or_none()
    if not instance:
        raise HTTPException(404, "Instance not found")
    
    if data.policy not in ["ACCEPT", "DROP"]:
        raise HTTPException(400, "Invalid policy")
    
    instance.firewall_default_policy = data.policy
    await db.commit()
    
    # TODO: Reapply firewall rules with new default policy
    
    return {"success": True, "policy": data.policy}
