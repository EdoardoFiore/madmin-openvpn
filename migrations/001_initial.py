"""
OpenVPN Module - Database Migration 001

Creates initial tables for OpenVPN instances, clients, groups, and rules.
"""
from sqlmodel import SQLModel
from sqlalchemy.ext.asyncio import AsyncEngine


async def upgrade(engine: AsyncEngine):
    """Create all OpenVPN module tables."""
    from .models import (
        OvpnInstance, OvpnClient, OvpnGroup, 
        OvpnGroupMember, OvpnGroupRule, OvpnMagicToken
    )
    
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all, tables=[
            OvpnInstance.__table__,
            OvpnClient.__table__,
            OvpnGroup.__table__,
            OvpnGroupMember.__table__,
            OvpnGroupRule.__table__,
            OvpnMagicToken.__table__,
        ])


async def downgrade(engine: AsyncEngine):
    """Drop all OpenVPN module tables."""
    from .models import (
        OvpnInstance, OvpnClient, OvpnGroup,
        OvpnGroupMember, OvpnGroupRule, OvpnMagicToken
    )
    
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.drop_all, tables=[
            OvpnMagicToken.__table__,
            OvpnGroupRule.__table__,
            OvpnGroupMember.__table__,
            OvpnGroup.__table__,
            OvpnClient.__table__,
            OvpnInstance.__table__,
        ])
