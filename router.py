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
from sqlalchemy import select, func, delete
from sqlmodel import SQLModel
import secrets
import qrcode

from core.database import get_session
from core.auth.dependencies import require_permission
from core.auth.models import User

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
            **inst.model_dump(exclude={"status", "clients", "groups"}),
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
    
    # Generate server config - write directly where systemd expects it
    config = openvpn_service.create_server_config(instance)
    config_path = OPENVPN_BASE_DIR / f"{instance_id}.conf"
    config_path.write_text(config)
    config_path.chmod(0o600)
    
    # Generate initial CRL
    openvpn_service.regenerate_crl(instance_id)
    
    await db.commit()
    
    return OvpnInstanceRead(
        **instance.model_dump(exclude={"status", "clients", "groups"}),
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
        **instance.model_dump(exclude={"status", "clients", "groups"}),
        status="running" if is_running else "stopped",
        client_count=client_count
    )


class OvpnInstanceUpdate(SQLModel):
    """Schema for updating instance settings."""
    name: Optional[str] = None
    endpoint: Optional[str] = None


@router.patch("/instances/{instance_id}")
async def update_instance(
    instance_id: str,
    data: OvpnInstanceUpdate,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("openvpn.manage"))
):
    """Update instance settings (name, endpoint)."""
    result = await db.execute(select(OvpnInstance).where(OvpnInstance.id == instance_id))
    instance = result.scalar_one_or_none()
    if not instance:
        raise HTTPException(404, "Instance not found")
    
    # Update fields
    if data.name is not None:
        instance.name = data.name
    if data.endpoint is not None:
        instance.endpoint = data.endpoint if data.endpoint else None
    
    instance.updated_at = datetime.utcnow()
    await db.commit()
    
    return {"success": True, "message": "Instance updated"}


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
    
    # Remove group chains first (needs DB access)
    from .service import OpenVPNService
    await OpenVPNService.remove_all_group_chains(instance.id, db)
    
    # Remove instance firewall rules
    openvpn_service.remove_instance_firewall_rules(instance_id)
    
    # Delete config file
    config_path = OPENVPN_BASE_DIR / f"{instance_id}.conf"
    if config_path.exists():
        config_path.unlink()
    
    # Delete magic tokens (no cascade configured on DB)
    from .models import OvpnMagicToken, OvpnClient
    await db.execute(
        delete(OvpnMagicToken).where(
            OvpnMagicToken.client_id.in_(
                select(OvpnClient.id).where(OvpnClient.instance_id == instance_id)
            )
        )
    )

    # Delete from database (cascades to clients, groups, etc.)
    await db.delete(instance)
    await db.commit()
    
    # Delete instance directory (PKI, CCD, etc.)
    import shutil
    instance_dir = openvpn_service.get_instance_dir(instance_id)
    if instance_dir.exists():
        shutil.rmtree(instance_dir)
    
    logger.info(f"Deleted instance {instance_id} and all related files")


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
        # Also apply group rules (member jumps, default policy)
        from .service import OpenVPNService
        await OpenVPNService.apply_group_firewall_rules(instance.id, db)
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
        # Remove firewall rules when interface stops
        from .service import OpenVPNService
        await OpenVPNService.remove_all_group_chains(instance.id, db)
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
    if data.dns_servers is not None:  # Allow empty list to clear DNS
        instance.dns_servers = data.dns_servers
    instance.updated_at = datetime.utcnow()
    
    await db.commit()
    await db.refresh(instance)
    
    # Regenerate config
    config = openvpn_service.create_server_config(instance)
    config_path = OPENVPN_BASE_DIR / f"{instance_id}.conf"
    config_path.write_text(config)
    
    # Reapply firewall if running
    if openvpn_service.get_instance_status(instance_id):
        openvpn_service.apply_instance_firewall_rules(
            instance_id, instance.port, instance.protocol,
            instance.interface, instance.subnet,
            instance.tunnel_mode, instance.routes
        )
    
    return {
        "success": True,
        "message": "Routing aggiornato. Le nuove rotte saranno attive alla prossima connessione dei client.",
        "tunnel_mode": instance.tunnel_mode,
        "routes": instance.routes
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
        
        live_connected_since = None
        if conn_info and conn_info.get('connected_since'):
            try:
                # Parse date: 2026-01-10 17:29:06
                live_connected_since = datetime.strptime(conn_info['connected_since'], "%Y-%m-%d %H:%M:%S")
            except ValueError:
                # Fallback or ignore parse error
                pass
        
        # Use live connection time if available, otherwise None (as requested by user to avoid stale data)
        display_last_connection = live_connected_since

        response.append(OvpnClientRead(
            id=client.id,
            name=client.name,
            allocated_ip=client.allocated_ip,
            cert_expiry=client.cert_expiry,
            cert_days_remaining=openvpn_service.get_cert_days_remaining(client.cert_expiry) if client.cert_expiry else None,
            revoked=client.revoked,
            created_at=client.created_at,
            last_connection=display_last_connection,
            is_connected=bool(conn_info),
            connected_since=live_connected_since,
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
    
    # Validate name (allow letters, numbers, dots, underscores, hyphens)
    if not re.match(r'^[a-zA-Z0-9._-]+$', data.name):
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
    
    # Remove from any group memberships (revoked clients shouldn't have firewall rules)
    await db.execute(
        OvpnGroupMember.__table__.delete().where(OvpnGroupMember.client_id == client.id)
    )
    
    # Mark as revoked
    client.revoked = True
    client.revoked_at = datetime.utcnow()
    await db.commit()
    
    # Reapply firewall rules (removes this client's jump rules)
    await openvpn_service.apply_group_firewall_rules(instance_id, db)


@router.delete("/instances/{instance_id}/clients/{client_name}/permanent", status_code=204)
async def delete_client_permanent(
    instance_id: str,
    client_name: str,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("openvpn.clients"))
):
    """Permanently delete a client (must be revoked first)."""
    result = await db.execute(
        select(OvpnClient).where(
            (OvpnClient.instance_id == instance_id) &
            (OvpnClient.name == client_name)
        )
    )
    client = result.scalar_one_or_none()
    if not client:
        raise HTTPException(404, "Client not found")
    
    if not client.revoked:
        raise HTTPException(400, "Client must be revoked before permanent deletion")
    
    # Remove from any group memberships
    await db.execute(
        OvpnGroupMember.__table__.delete().where(OvpnGroupMember.client_id == client.id)
    )
    
    # Remove from database
    await db.delete(client)
    await db.commit()
    
    logger.info(f"Permanently deleted client {client_name} from instance {instance_id}")


@router.post("/instances/{instance_id}/clients/{client_name}/restore")
async def restore_client(
    instance_id: str,
    client_name: str,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("openvpn.clients"))
):
    """Restore a revoked client by generating a new certificate."""
    # Get instance
    inst_result = await db.execute(select(OvpnInstance).where(OvpnInstance.id == instance_id))
    instance = inst_result.scalar_one_or_none()
    if not instance:
        raise HTTPException(404, "Instance not found")
    
    # Get client
    result = await db.execute(
        select(OvpnClient).where(
            (OvpnClient.instance_id == instance_id) &
            (OvpnClient.name == client_name)
        )
    )
    client = result.scalar_one_or_none()
    if not client:
        raise HTTPException(404, "Client not found")
    
    if not client.revoked:
        raise HTTPException(400, "Client is not revoked")
    
    # Generate new certificate (this will create a new cert with same name)
    cert_result = openvpn_service.generate_client_cert(instance_id, client_name, instance.cert_duration_days)
    if not cert_result.get("success"):
        raise HTTPException(500, f"Failed to generate new certificate: {cert_result.get('error')}")
    
    # Recreate CCD file for static IP
    openvpn_service.create_ccd_file(instance_id, client_name, client.allocated_ip)
    
    # Update client record
    client.revoked = False
    client.revoked_at = None
    client.cert_expiry = cert_result.get("expiry")
    client.cert_fingerprint = cert_result.get("fingerprint")
    await db.commit()
    
    return {
        "success": True,
        "message": "Client restored with new certificate",
        "new_expiry": cert_result.get("expiry"),
        "note": "Client must download the new configuration"
    }


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
    from .service import get_public_ip
    endpoint = instance.endpoint or get_public_ip() or "YOUR_SERVER_IP"
    
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
# CONFIG SHARING (EMAIL + MAGIC TOKEN)
# =========================================================================

@router.post("/instances/{instance_id}/clients/{client_name}/send-config")
async def send_client_config_email(
    instance_id: str,
    client_name: str,
    data: SendConfigRequest,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("openvpn.clients"))
):
    """
    Send client config via email with magic token link.
    Token is valid for 48 hours and can only be used once.
    """
    from core.settings.models import SMTPSettings
    from core.email import send_email
    
    # Get instance and client
    result = await db.execute(select(OvpnInstance).where(OvpnInstance.id == instance_id))
    instance = result.scalar_one_or_none()
    if not instance:
        raise HTTPException(404, "Instance not found")
    
    result = await db.execute(
        select(OvpnClient).where(
            (OvpnClient.instance_id == instance_id) & (OvpnClient.name == client_name)
        )
    )
    client = result.scalar_one_or_none()
    if not client:
        raise HTTPException(404, "Client not found")
    
    if client.revoked:
        raise HTTPException(400, "Cannot send config for revoked client")
    
    # Get SMTP settings
    smtp_result = await db.execute(select(SMTPSettings).where(SMTPSettings.id == 1))
    smtp_settings = smtp_result.scalar_one_or_none()
    if not smtp_settings or not smtp_settings.smtp_host:
        raise HTTPException(400, "SMTP non configurato. Configura prima le impostazioni email.")
    
    if not smtp_settings.public_url:
        raise HTTPException(400, "URL pubblico non configurato nelle impostazioni SMTP.")
    
    # Generate magic token
    token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(hours=48)
    
    magic_token = OvpnMagicToken(
        token=token,
        client_id=client.id,
        expires_at=expires_at
    )
    db.add(magic_token)
    await db.commit()
    
    # Build download URL
    base_url = smtp_settings.public_url.rstrip('/')
    download_url = f"{base_url}/api/modules/openvpn/download/{token}"
    
    # Send email
    body_html = f"""
    <html>
    <body style="font-family: Arial, sans-serif; padding: 20px; background-color: #f5f5f5;">
        <div style="max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px;">
            <h2 style="color: #ea580c;">🔐 Configurazione VPN OpenVPN</h2>
            <p>Ciao,</p>
            <p>Ecco il link per scaricare la tua configurazione VPN:</p>
            <p style="text-align: center; margin: 30px 0;">
                <a href="{download_url}" 
                   style="background: #ea580c; color: white; padding: 12px 24px; 
                          text-decoration: none; border-radius: 6px; font-weight: bold;">
                    📥 Scarica Configurazione
                </a>
            </p>
            <p><strong>Client:</strong> {client_name}</p>
            <p><strong>Istanza:</strong> {instance.name}</p>
            <hr style="border: none; border-top: 1px solid #e0e0e0; margin: 20px 0;">
            <p style="color: #666; font-size: 12px;">
                ⚠️ Questo link è valido per <strong>48 ore</strong> e può essere usato <strong>una sola volta</strong>.<br>
                Dopo il download il link non sarà più utilizzabile.
            </p>
        </div>
    </body>
    </html>
    """
    
    result = await send_email(
        smtp_host=smtp_settings.smtp_host,
        smtp_port=smtp_settings.smtp_port,
        smtp_encryption=smtp_settings.smtp_encryption,
        smtp_username=smtp_settings.smtp_username,
        smtp_password=smtp_settings.smtp_password,
        sender_email=smtp_settings.sender_email,
        sender_name=smtp_settings.sender_name,
        recipient_email=data.email,
        subject=f"VPN Config - {client_name}",
        body_html=body_html
    )
    
    if not result.get("success"):
        raise HTTPException(500, result.get("message", "Errore invio email"))
    
    return {"success": True, "message": f"Email inviata a {data.email}"}


async def _validate_token(token: str, db: AsyncSession):
    """
    Validate magic token and return (magic_token, client, instance, error) tuple.
    If error is not None, it contains (title, message) for the error page.
    Token can be used multiple times within validity period.
    """
    result = await db.execute(select(OvpnMagicToken).where(OvpnMagicToken.token == token))
    magic_token = result.scalar_one_or_none()
    
    if not magic_token:
        return None, None, None, ("Link non valido", "Questo link di download non esiste o è stato rimosso.")
    
    if magic_token.expires_at < datetime.utcnow():
        return None, None, None, ("Link scaduto", "Questo link di download è scaduto. Richiedi un nuovo link all'amministratore.")
    
    result = await db.execute(select(OvpnClient).where(OvpnClient.id == magic_token.client_id))
    client = result.scalar_one_or_none()
    if not client:
        return None, None, None, ("Client non trovato", "Il client associato a questo link non esiste più.")
    
    result = await db.execute(select(OvpnInstance).where(OvpnInstance.id == client.instance_id))
    instance = result.scalar_one_or_none()
    if not instance:
        return None, None, None, ("Istanza non trovata", "L'istanza VPN associata non esiste più.")
    
    return magic_token, client, instance, None


@router.get("/download/{token}", response_class=HTMLResponse)
async def download_landing_page(
    token: str,
    db: AsyncSession = Depends(get_session)
):
    """
    Public landing page with setup instructions for OpenVPN.
    Shows mobile/desktop tabs with download buttons.
    """
    from pathlib import Path
    
    magic_token, client, instance, error = await _validate_token(token, db)
    
    # If error, show error page
    if error:
        error_template = Path(__file__).parent / "static" / "link_error.html"
        html_content = error_template.read_text(encoding="utf-8")
        html_content = html_content.replace("{title}", error[0])
        html_content = html_content.replace("{message}", error[1])
        return HTMLResponse(content=html_content, status_code=410)
    
    # Load and render template
    template_path = Path(__file__).parent / "static" / "download_page.html"
    html_content = template_path.read_text(encoding="utf-8")
    
    # Format expiry date
    expires_str = magic_token.expires_at.strftime("%d/%m/%Y alle %H:%M")
    
    # Build URLs
    base_path = f"/api/modules/openvpn/download/{token}"
    
    html_content = html_content.replace("{client_name}", client.name)
    html_content = html_content.replace("{expires_at}", expires_str)
    html_content = html_content.replace("{download_url}", f"{base_path}/file")
    
    return HTMLResponse(content=html_content)


@router.get("/download/{token}/file")
async def download_config_file(
    token: str,
    db: AsyncSession = Depends(get_session)
):
    """
    Download the actual .ovpn file.
    Can be downloaded multiple times within validity period.
    """
    from .service import get_public_ip
    from pathlib import Path
    
    magic_token, client, instance, error = await _validate_token(token, db)
    
    # If error, show error page
    if error:
        error_template = Path(__file__).parent / "static" / "link_error.html"
        html_content = error_template.read_text(encoding="utf-8")
        html_content = html_content.replace("{title}", error[0])
        html_content = html_content.replace("{message}", error[1])
        return HTMLResponse(content=html_content, status_code=410)
    
    # Generate config
    endpoint = instance.endpoint or get_public_ip() or "YOUR_SERVER_IP"
    config = openvpn_service.generate_client_config(instance, client, endpoint)
    
    return Response(
        content=config,
        media_type="text/plain",
        headers={"Content-Disposition": f"attachment; filename={client.name}.ovpn"}
    )


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
    
    # IMPORTANT: Remove firewall rules BEFORE deleting from DB
    # so we still have member info to remove jump rules
    await openvpn_service.remove_group_firewall_rules(instance_id, group_id, group.name, db)
    
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
    
    # Apply firewall rules for this instance
    await openvpn_service.apply_group_firewall_rules(instance_id, db)
    
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
    
    await db.delete(member)
    await db.commit()
    
    # Reapply firewall rules
    await openvpn_service.apply_group_firewall_rules(instance_id, db)


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
    
    # Apply firewall rules
    await openvpn_service.apply_group_firewall_rules(instance_id, db)
    
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
    
    # Apply firewall rules
    await openvpn_service.apply_group_firewall_rules(instance_id, db)
    
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
    
    await db.delete(rule)
    await db.commit()
    
    # Reapply firewall rules
    await openvpn_service.apply_group_firewall_rules(instance_id, db)


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
    
    # Reapply firewall rules with new order
    await openvpn_service.apply_group_firewall_rules(instance_id, db)
    
    return {"success": True}


# =========================================================================
# FIREWALL POLICY
# =========================================================================

@router.patch("/instances/{instance_id}/firewall-policy")
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
    
    # Reapply firewall rules with new policy
    await openvpn_service.apply_group_firewall_rules(instance_id, db)
    
    return {"success": True, "policy": data.policy}
