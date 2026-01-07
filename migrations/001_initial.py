"""
OpenVPN Module - Initial Database Migration

Creates OpenVPN tables using direct engine access.
"""
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import SQLModel


async def upgrade(session: AsyncSession) -> None:
    """Create OpenVPN module tables."""
    # Import models to register them in SQLModel metadata
    from modules.openvpn.models import (
        OvpnInstance, OvpnClient, OvpnGroup,
        OvpnGroupMember, OvpnGroupRule, OvpnMagicToken
    )
    
    # Import the engine directly from database module
    from core.database import engine
    
    # Use the engine directly for DDL operations
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    
    print("OpenVPN module tables created")


async def downgrade(session: AsyncSession) -> None:
    """Drop OpenVPN module tables."""
    from core.database import engine
    from sqlalchemy import text
    
    tables = ["ovpn_magic_token", "ovpn_group_rule", "ovpn_group_member", 
              "ovpn_client", "ovpn_group", "ovpn_instance"]
    
    async with engine.begin() as conn:
        for table in tables:
            await conn.execute(text(f"DROP TABLE IF EXISTS {table} CASCADE"))
