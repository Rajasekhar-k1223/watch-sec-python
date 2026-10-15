"""
pg_pagination.py — Keyset (cursor) pagination for Monitorix FastAPI backend.

Why keyset > OFFSET?
  - OFFSET N forces PostgreSQL to scan and discard N rows every request.
  - At page 100 with limit 100, that's 10,000 wasted rows per request.
  - Keyset pagination uses a WHERE clause: `WHERE id > last_seen_id`
    which hits the primary-key index directly — O(log n) instead of O(n).

Applies to: EventLogs, ActivityLogs, Screenshots, AgentReports, DetectionAlerts.

Usage in a FastAPI endpoint:
    from app.db.pg_pagination import keyset_page, KeysetParams

    @router.get("/events/{agent_id}")
    async def get_events(
        agent_id: str,
        db: AsyncSession = Depends(get_db),
        # Standard OFFSET (backward compat)
        limit: int = Query(100, ge=1, le=1000),
        offset: int = Query(0, ge=0),
        # New cursor param (preferred for large datasets)
        cursor: Optional[int] = Query(None, description="Last seen ID for keyset pagination"),
        cursor_dir: str = Query("next", regex="^(next|prev)$"),
    ):
        page = await keyset_page(
            db=db,
            model=EventLog,
            cursor_col="Id",
            order_col="Timestamp",
            filters=[EventLog.AgentId == agent_id],
            cursor=cursor,
            cursor_dir=cursor_dir,
            limit=limit,
            offset=offset,  # fallback if cursor is None
        )
        return page
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Optional, Type

from sqlalchemy import Column, asc, desc, select  # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession  # type: ignore
from sqlalchemy.orm import DeclarativeMeta  # type: ignore

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class KeysetPage:
    """Response envelope for a keyset-paginated result set."""

    items: list[Any]
    """The actual data rows (SQLAlchemy model instances or dicts)."""

    next_cursor: Optional[int]
    """Pass this as `cursor` in the next request to get the next page."""

    prev_cursor: Optional[int]
    """Pass this as `cursor` with `cursor_dir=prev` to get the previous page."""

    has_next: bool
    """True if there are more rows beyond this page."""

    limit: int
    """Page size used for this request."""

    total_returned: int
    """Number of items in this page (may be < limit on last page)."""

    metadata: dict = field(default_factory=dict)
    """Optional extra metadata (e.g., total count if requested)."""

    def to_dict(self) -> dict:
        return {
            "items": self.items,
            "pagination": {
                "next_cursor": self.next_cursor,
                "prev_cursor": self.prev_cursor,
                "has_next": self.has_next,
                "limit": self.limit,
                "total_returned": self.total_returned,
                **self.metadata,
            },
        }


# ---------------------------------------------------------------------------
# Core keyset pagination function
# ---------------------------------------------------------------------------

async def keyset_page(
    db: AsyncSession,
    model: Type[Any],
    *,
    cursor_col: str = "Id",
    order_col: str = "Timestamp",
    filters: Optional[list] = None,
    cursor: Optional[int] = None,
    cursor_dir: str = "next",
    limit: int = 100,
    offset: int = 0,
    order: str = "desc",
    as_dict: bool = False,
) -> KeysetPage:
    """
    Perform keyset (cursor-based) pagination on any SQLAlchemy model.

    Parameters
    ----------
    db          : SQLAlchemy AsyncSession
    model       : The ORM model class (e.g., EventLog, ActivityLog)
    cursor_col  : Column name to use as the cursor (must be indexed, usually "Id")
    order_col   : Column to ORDER BY (usually "Timestamp")
    filters     : List of SQLAlchemy filter expressions (WHERE clauses)
    cursor      : Last seen cursor value from previous page (None = first page)
    cursor_dir  : "next" (forward) or "prev" (backward)
    limit       : Number of rows per page
    offset      : Fallback OFFSET — used when cursor is None (first page only)
    order       : "desc" (newest first) or "asc" (oldest first)
    as_dict     : If True, convert rows to dicts; else return model instances

    Returns
    -------
    KeysetPage  : Paginated result with cursor metadata
    """
    cursor_column: Column = getattr(model, cursor_col)
    order_column: Column  = getattr(model, order_col)

    # Build base query
    q = select(model)

    # Apply caller-provided filters
    for f in (filters or []):
        q = q.where(f)

    # Apply cursor condition
    if cursor is not None:
        if cursor_dir == "next":
            if order == "desc":
                q = q.where(cursor_column < cursor)
            else:
                q = q.where(cursor_column > cursor)
        else:  # prev
            if order == "desc":
                q = q.where(cursor_column > cursor)
            else:
                q = q.where(cursor_column < cursor)

    # Apply ordering
    if order == "desc":
        q = q.order_by(desc(order_column), desc(cursor_column))
    else:
        q = q.order_by(asc(order_column), asc(cursor_column))

    # Fetch limit + 1 to detect if there's a next page
    fetch_limit = limit + 1

    # Fall back to OFFSET only on the first page (cursor is None)
    if cursor is None and offset > 0:
        q = q.offset(offset)

    q = q.limit(fetch_limit)

    result = await db.execute(q)
    rows = result.scalars().all()

    has_next = len(rows) > limit
    items = rows[:limit]

    # Determine next/prev cursors
    next_cursor: Optional[int] = None
    prev_cursor: Optional[int] = None

    if items:
        first_id = getattr(items[0], cursor_col)
        last_id  = getattr(items[-1], cursor_col)

        if order == "desc":
            next_cursor = last_id  if has_next else None
            prev_cursor = first_id if cursor is not None else None
        else:
            next_cursor = last_id  if has_next else None
            prev_cursor = first_id if cursor is not None else None

    if as_dict:
        items = [
            {c.key: getattr(row, c.key) for c in row.__table__.columns}
            for row in items
        ]

    return KeysetPage(
        items=items,
        next_cursor=next_cursor,
        prev_cursor=prev_cursor,
        has_next=has_next,
        limit=limit,
        total_returned=len(items),
    )


# ---------------------------------------------------------------------------
# Pre-configured paginators for the main hot tables
# ---------------------------------------------------------------------------

async def paginate_activity_logs(
    db: AsyncSession,
    agent_id: str,
    tenant_id: Optional[int] = None,
    *,
    cursor: Optional[int] = None,
    limit: int = 100,
    offset: int = 0,
    start_ts=None,
    end_ts=None,
    risk_level: Optional[str] = None,
    as_dict: bool = True,
) -> KeysetPage:
    """Keyset-paginated ActivityLogs for a specific agent."""
    from .models import ActivityLog as ActivityLogModel  # type: ignore

    filters = [ActivityLogModel.AgentId == agent_id]
    if tenant_id:
        filters.append(ActivityLogModel.TenantId == tenant_id)
    if start_ts:
        filters.append(ActivityLogModel.Timestamp >= start_ts)
    if end_ts:
        filters.append(ActivityLogModel.Timestamp <= end_ts)
    if risk_level:
        filters.append(ActivityLogModel.RiskLevel == risk_level)

    return await keyset_page(
        db=db,
        model=ActivityLogModel,
        cursor_col="Id",
        order_col="Timestamp",
        filters=filters,
        cursor=cursor,
        limit=limit,
        offset=offset,
        order="desc",
        as_dict=as_dict,
    )


async def paginate_event_logs(
    db: AsyncSession,
    agent_id: str,
    *,
    cursor: Optional[int] = None,
    limit: int = 100,
    offset: int = 0,
    start_ts=None,
    end_ts=None,
    event_type: Optional[str] = None,
    as_dict: bool = True,
) -> KeysetPage:
    """Keyset-paginated EventLogs for a specific agent."""
    from .models import EventLog  # type: ignore

    filters: list[Any] = [EventLog.AgentId == agent_id]
    if start_ts:
        filters.append(EventLog.Timestamp >= start_ts)
    if end_ts:
        filters.append(EventLog.Timestamp <= end_ts)
    if event_type:
        filters.append(EventLog.Type == event_type)

    return await keyset_page(
        db=db,
        model=EventLog,
        cursor_col="Id",
        order_col="Timestamp",
        filters=filters,
        cursor=cursor,
        limit=limit,
        offset=offset,
        order="desc",
        as_dict=as_dict,
    )


async def paginate_screenshots(
    db: AsyncSession,
    agent_id: str,
    tenant_id: Optional[int] = None,
    *,
    cursor: Optional[int] = None,
    limit: int = 50,
    offset: int = 0,
    alerts_only: bool = False,
    as_dict: bool = True,
) -> KeysetPage:
    """Keyset-paginated Screenshots for a specific agent."""
    from .models import Screenshot  # type: ignore

    filters: list[Any] = [Screenshot.AgentId == agent_id]
    if tenant_id:
        filters.append(Screenshot.TenantId == tenant_id)
    if alerts_only:
        filters.append(Screenshot.IsAlert == True)  # noqa: E712

    return await keyset_page(
        db=db,
        model=Screenshot,
        cursor_col="Id",
        order_col="Timestamp",
        filters=filters,
        cursor=cursor,
        limit=limit,
        offset=offset,
        order="desc",
        as_dict=as_dict,
    )


async def paginate_agent_reports(
    db: AsyncSession,
    agent_id: str,
    tenant_id: Optional[int] = None,
    *,
    cursor: Optional[int] = None,
    limit: int = 100,
    offset: int = 0,
    start_ts=None,
    end_ts=None,
    as_dict: bool = True,
) -> KeysetPage:
    """Keyset-paginated AgentReports for a specific agent."""
    from .models import AgentReportEntity  # type: ignore

    filters: list[Any] = [AgentReportEntity.AgentId == agent_id]
    if tenant_id:
        filters.append(AgentReportEntity.TenantId == tenant_id)
    if start_ts:
        filters.append(AgentReportEntity.Timestamp >= start_ts)
    if end_ts:
        filters.append(AgentReportEntity.Timestamp <= end_ts)

    return await keyset_page(
        db=db,
        model=AgentReportEntity,
        cursor_col="Id",
        order_col="Timestamp",
        filters=filters,
        cursor=cursor,
        limit=limit,
        offset=offset,
        order="desc",
        as_dict=as_dict,
    )


async def paginate_detection_alerts(
    db: AsyncSession,
    agent_id: str,
    *,
    cursor: Optional[int] = None,
    limit: int = 100,
    offset: int = 0,
    status: Optional[str] = None,
    as_dict: bool = True,
) -> KeysetPage:
    """Keyset-paginated DetectionAlerts for a specific agent."""
    from .models import DetectionAlert  # type: ignore

    filters: list[Any] = [DetectionAlert.AgentId == agent_id]
    if status:
        filters.append(DetectionAlert.Status == status)

    return await keyset_page(
        db=db,
        model=DetectionAlert,
        cursor_col="Id",
        order_col="Timestamp",
        filters=filters,
        cursor=cursor,
        limit=limit,
        offset=offset,
        order="desc",
        as_dict=as_dict,
    )
