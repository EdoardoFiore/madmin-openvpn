"""
OpenVPN Module - Database Models

SQLModel tables for OpenVPN instances, clients, groups, and rules.
Includes PKI certificate tracking and CCD for static IP assignment.
"""
from typing import Optional, List, Dict
from datetime import datetime
from sqlmodel import Field, SQLModel, Relationship, JSON, Column
import uuid


class OvpnInstance(SQLModel, table=True):
    """OpenVPN server instance with PKI."""
    __tablename__ = "ovpn_instance"
    
    id: str = Field(primary_key=True)  # e.g., "office", "remote"
    name: str = Field(max_length=100)
    port: int = Field(unique=True)
    protocol: str = Field(default="udp", max_length=10)  # "udp" or "tcp"
    subnet: str = Field(max_length=50)  # e.g., "10.8.0.0/24"
    interface: str = Field(unique=True, max_length=20)  # e.g., "tun0"
    
    # Configuration
    tunnel_mode: str = Field(default="full")  # "full" or "split"
    routes: List[Dict] = Field(default=[], sa_column=Column(JSON))
    dns_servers: List[str] = Field(default=["8.8.8.8", "1.1.1.1"], sa_column=Column(JSON))
    
    # Encryption settings
    cipher: str = Field(default="AES-256-GCM", max_length=50)
    auth: str = Field(default="SHA256", max_length=20)  # HMAC algorithm
    tls_version_min: str = Field(default="1.2", max_length=10)
    
    # PKI - stored paths, actual certs on filesystem
    # /etc/openvpn/server/{id}/easy-rsa/pki/
    ca_cert_expiry: Optional[datetime] = None
    server_cert_expiry: Optional[datetime] = None
    cert_duration_days: int = Field(default=3650)  # Default 10 years
    
    # Firewall
    firewall_default_policy: str = Field(default="ACCEPT")
    
    # Status
    status: str = Field(default="stopped")  # "stopped", "running"
    endpoint: Optional[str] = Field(default=None, max_length=255)
    
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    
    # Relationships
    clients: List["OvpnClient"] = Relationship(
        back_populates="instance",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"}
    )
    groups: List["OvpnGroup"] = Relationship(
        back_populates="instance",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"}
    )


class OvpnClient(SQLModel, table=True):
    """OpenVPN client with certificate tracking."""
    __tablename__ = "ovpn_client"
    
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    instance_id: str = Field(foreign_key="ovpn_instance.id", index=True)
    name: str = Field(max_length=100)
    
    # Static IP (assigned via CCD)
    allocated_ip: str = Field(max_length=50)
    
    # Certificate tracking
    cert_expiry: Optional[datetime] = None
    cert_fingerprint: Optional[str] = Field(default=None, max_length=100)
    
    # Status
    revoked: bool = Field(default=False)
    revoked_at: Optional[datetime] = None
    
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_connection: Optional[datetime] = None
    
    # Relationships
    instance: "OvpnInstance" = Relationship(back_populates="clients")
    group_links: List["OvpnGroupMember"] = Relationship(
        back_populates="client",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"}
    )


class OvpnGroup(SQLModel, table=True):
    """Firewall group for OpenVPN clients."""
    __tablename__ = "ovpn_group"
    
    id: str = Field(primary_key=True)
    instance_id: str = Field(foreign_key="ovpn_instance.id", index=True)
    name: str = Field(max_length=100)
    description: str = Field(default="", max_length=500)
    order: int = Field(default=0)  # Lower = higher priority in iptables
    
    # Relationships
    instance: "OvpnInstance" = Relationship(back_populates="groups")
    client_links: List["OvpnGroupMember"] = Relationship(
        back_populates="group",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"}
    )
    rules: List["OvpnGroupRule"] = Relationship(
        back_populates="group",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"}
    )


class OvpnGroupMember(SQLModel, table=True):
    """Junction table for groups and clients."""
    __tablename__ = "ovpn_group_member"
    
    group_id: str = Field(foreign_key="ovpn_group.id", primary_key=True)
    client_id: uuid.UUID = Field(foreign_key="ovpn_client.id", primary_key=True)
    
    group: "OvpnGroup" = Relationship(back_populates="client_links")
    client: "OvpnClient" = Relationship(back_populates="group_links")


class OvpnGroupRule(SQLModel, table=True):
    """Firewall rule for a group."""
    __tablename__ = "ovpn_group_rule"
    
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    group_id: str = Field(foreign_key="ovpn_group.id", index=True)
    
    action: str  # ACCEPT, DROP
    protocol: str  # tcp, udp, icmp, all
    port: Optional[str] = None
    destination: str
    description: str = Field(default="", max_length=255)
    order: int = Field(default=0)
    
    group: "OvpnGroup" = Relationship(back_populates="rules")


class OvpnMagicToken(SQLModel, table=True):
    """Temporary token for client config sharing."""
    __tablename__ = "ovpn_magic_token"
    
    token: str = Field(primary_key=True)
    client_id: uuid.UUID = Field(foreign_key="ovpn_client.id", index=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime
    used: bool = Field(default=False)


# --- Pydantic Schemas ---

class OvpnInstanceCreate(SQLModel):
    name: str
    port: int
    protocol: str = "udp"
    subnet: str
    tunnel_mode: str = "full"
    routes: List[Dict] = []
    dns_servers: List[str] = ["8.8.8.8", "1.1.1.1"]
    cipher: str = "AES-256-GCM"
    cert_duration_days: int = 3650
    endpoint: Optional[str] = None


class OvpnInstanceRead(SQLModel):
    id: str
    name: str
    port: int
    protocol: str
    subnet: str
    interface: str
    tunnel_mode: str
    routes: List[Dict]
    dns_servers: List[str]
    cipher: str
    auth: str
    firewall_default_policy: str
    status: str
    endpoint: Optional[str] = None
    ca_cert_expiry: Optional[datetime] = None
    server_cert_expiry: Optional[datetime] = None
    client_count: int = 0


class OvpnClientCreate(SQLModel):
    name: str
    cert_duration_days: Optional[int] = None  # Use instance default if not specified
    group_id: Optional[str] = None  # Optional: assign client to group during creation


class OvpnClientRead(SQLModel):
    id: uuid.UUID
    name: str
    allocated_ip: str
    cert_expiry: Optional[datetime]
    cert_days_remaining: Optional[int] = None
    revoked: bool
    created_at: datetime
    last_connection: Optional[datetime]
    # Live status fields (from management interface)
    is_connected: Optional[bool] = None
    bytes_received: Optional[int] = None
    bytes_sent: Optional[int] = None
    connected_since: Optional[datetime] = None


# --- Group Schemas ---

class SendConfigRequest(SQLModel):
    """Request schema for sending client config via email."""
    email: str


class OvpnGroupCreate(SQLModel):
    name: str
    description: str = ""


class OvpnGroupRead(SQLModel):
    id: str
    instance_id: str
    name: str
    description: str
    order: int = 0
    member_count: int = 0
    rule_count: int = 0


class OvpnGroupMemberRead(SQLModel):
    client_id: uuid.UUID
    client_name: str
    client_ip: str


# --- Rule Schemas ---

class OvpnGroupRuleCreate(SQLModel):
    action: str  # ACCEPT, DROP
    protocol: str  # tcp, udp, icmp, all
    port: Optional[str] = None
    destination: str
    description: str = ""


class OvpnGroupRuleRead(SQLModel):
    id: uuid.UUID
    action: str
    protocol: str
    port: Optional[str]
    destination: str
    description: str
    order: int


class OvpnGroupRuleUpdate(SQLModel):
    action: Optional[str] = None
    protocol: Optional[str] = None
    port: Optional[str] = None
    destination: Optional[str] = None
    description: Optional[str] = None


class RuleOrderUpdate(SQLModel):
    id: uuid.UUID
    order: int


class FirewallPolicyUpdate(SQLModel):
    policy: str  # ACCEPT or DROP


class OvpnRoutingUpdate(SQLModel):
    """Schema for updating instance routing mode."""
    tunnel_mode: str  # "full" or "split"
    routes: List[Dict] = []  # Required when tunnel_mode is "split"
    dns_servers: Optional[List[str]] = None


# --- PKI Schemas ---

class PKIStatusRead(SQLModel):
    """PKI status for an instance."""
    ca_expiry: Optional[datetime] = None
    ca_days_remaining: Optional[int] = None
    server_cert_expiry: Optional[datetime] = None
    server_cert_days_remaining: Optional[int] = None
    crl_last_update: Optional[datetime] = None
    revoked_clients_count: int = 0


class CertRenewRequest(SQLModel):
    """Request to renew a certificate."""
    duration_days: Optional[int] = None  # Use default if not specified
