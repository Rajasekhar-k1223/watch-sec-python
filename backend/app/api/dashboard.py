from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import desc, func, case
from typing import List, Optional
from datetime import datetime, timedelta

from ..db.session import get_db, get_mongo_db
from ..db.models import AgentReportEntity, Agent, User
from .deps import get_current_user
from motor.motor_asyncio import AsyncIOMotorClient

router = APIRouter()

@router.get("/status")
async def get_dashboard_status(
    tenantId: Optional[int] = None, 
    db: AsyncSession = Depends(get_db),
    current_user: "User" = Depends(get_current_user)
):
    # 1. Fetch Agents for metadata
    agent_query = select(Agent)
    if tenantId:
       agent_query = agent_query.where(Agent.TenantId == tenantId)
    agent_result = await db.execute(agent_query)
    agents_map = {a.AgentId: a for a in agent_result.scalars().all()}

    # 2. Fetch Latest Reports for Status Calculation
    # Optimized: Instead of fetching all reports, we should try to get latest per agent.
    # For now, sticking to previous logic but identifying we need "Latest" status.
    query = select(AgentReportEntity).order_by(desc(AgentReportEntity.Timestamp))
    if tenantId:
        query = query.where(AgentReportEntity.TenantId == tenantId)
    
    # Limit to reasonable recent history to avoid fetching millions of rows if table is huge
    # assuming we just want current status, last 24h is enough.
    threshold = datetime.utcnow() - timedelta(hours=24)
    query = query.where(AgentReportEntity.Timestamp >= threshold)

    result = await db.execute(query)
    all_reports = result.scalars().all()

    latest = {}
    
    # Pre-fill with known agents from Agent table (so even if no report in last 24h, they appear as offline)
    for agent_id, agent in agents_map.items():
        latest[agent_id] = {
            "agentId": agent_id,
            "status": "Offline",
            "cpuUsage": 0,
            "memoryUsage": 0,
            "timestamp": agent.LastSeen.isoformat() if agent.LastSeen else datetime.utcnow().isoformat(),
            "hostname": agent.Hostname or "Unknown",
            "latitude": 0.0,
            "longitude": 0.0
        }

    # Update with latest report data
    for r in all_reports:
        # Since we ordered DESC, the first time we see an AgentId is its latest report
        if r.AgentId in latest and latest[r.AgentId].get("_processed"):
             continue
        
        # Calculate Status
        now_utc = datetime.utcnow()
        # time_diff = (now_utc - r.Timestamp).total_seconds()
        # Using server-side 2 min threshold for Online
        computed_status = "Online" if (now_utc - r.Timestamp).total_seconds() < 120 else "Offline"
        
        if r.AgentId not in latest:
             latest[r.AgentId] = {} # Should have been prefilled, but safe fallback

        ts_str = r.Timestamp.isoformat()
        if not ts_str.endswith("Z"): ts_str += "Z"

        latest[r.AgentId].update({
            "agentId": r.AgentId,
            "status": computed_status,
            "cpuUsage": r.CpuUsage,
            "memoryUsage": r.MemoryUsage,
            "timestamp": ts_str,
            "hostname": agents_map[r.AgentId].Hostname if r.AgentId in agents_map else "Unknown",
            "_processed": True # Flag to skip older reports for this agent
        })

    # Remove the internal flag before return
    for v in latest.values():
        if "_processed" in v: del v["_processed"]

    return list(latest.values())

@router.get("/dashboard/stats")
async def get_dashboard_stats(
    hours: int = 24,
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
    tenantId: Optional[int] = None, 
    db: AsyncSession = Depends(get_db),
    mongo: AsyncIOMotorClient = Depends(get_mongo_db),
    current_user: "User" = Depends(get_current_user)
):
    # 0. Time Range Logic
    now_utc = datetime.utcnow()
    
    if from_date:
        try:
            start_dt = datetime.fromisoformat(from_date.replace('Z', '+00:00'))
        except:
            start_dt = now_utc - timedelta(hours=hours) # Fallback
    else:
        start_dt = now_utc - timedelta(hours=hours)

    if to_date:
        try:
            end_dt = datetime.fromisoformat(to_date.replace('Z', '+00:00'))
        except:
            end_dt = now_utc
    else:
        end_dt = now_utc

    # Ensure naive datetimes are treated as UTC if ISO parsing didn't set tz
    if start_dt.tzinfo is not None: start_dt = start_dt.replace(tzinfo=None)
    if end_dt.tzinfo is not None: end_dt = end_dt.replace(tzinfo=None)

    total_hours = (end_dt - start_dt).total_seconds() / 3600
    
    # 1. Agent Stats (Online/Offline) - Snapshot (Always 'Now' for status, or could use range if supported)
    # Status is typically "Current", so we keep the standard "Last 2 mins" check for Online/Offline counts
    # regardless of history range, OR we can show "Active in range".
    # Let's stick to CURRENT status for the gauge, but Trends for the range.
    
    try:
        total_agents = 0
        online_agents = 0
        
        # Get total registered agents
        q_total = select(func.count(Agent.Id))
        if tenantId: q_total = q_total.where(Agent.TenantId == tenantId)
        total_res = await db.execute(q_total)
        total_agents = total_res.scalar() or 0
        
        # Get Online Count (Active in last 2 mins)
        threshold_online = now_utc - timedelta(minutes=2)
        q_online = select(func.count(func.distinct(AgentReportEntity.AgentId))).where(AgentReportEntity.Timestamp >= threshold_online)
        if tenantId: q_online = q_online.where(AgentReportEntity.TenantId == tenantId)
        online_res = await db.execute(q_online)
        online_agents = online_res.scalar() or 0
        
        offline_agents = max(0, total_agents - online_agents)

        # 2. Resources (Avg over RANGE)
        q_res = select(
            func.avg(AgentReportEntity.CpuUsage),
            func.avg(AgentReportEntity.MemoryUsage)
        ).where(AgentReportEntity.Timestamp >= start_dt).where(AgentReportEntity.Timestamp <= end_dt)
        if tenantId: q_res = q_res.where(AgentReportEntity.TenantId == tenantId)
        
        res_avg = await db.execute(q_res)
        avg_cpu, avg_mem = res_avg.one()
        avg_cpu = float(avg_cpu or 0)
        avg_mem = float(avg_mem or 0)

        # 3. Resource Trend
        q_trend = select(AgentReportEntity.Timestamp, AgentReportEntity.CpuUsage, AgentReportEntity.MemoryUsage)\
            .where(AgentReportEntity.Timestamp >= start_dt)\
            .where(AgentReportEntity.Timestamp <= end_dt)\
            .order_by(AgentReportEntity.Timestamp)
        
        if tenantId: q_trend = q_trend.where(AgentReportEntity.TenantId == tenantId)
        
        # Limit rows to prevent massive fetch
        trend_res = await db.execute(q_trend.limit(5000)) 
        items = trend_res.all()
        
        # Dynamic Grouping
        # If range < 48h -> Group by Hour
        # If range > 48h -> Group by Day
        group_by_day = total_hours > 48
        
        buckets = {}
        for ts, cpu, mem in items:
            key = ts.strftime("%Y-%m-%d") if group_by_day else ts.strftime("%Y-%m-%d %H:00")
            if key not in buckets: buckets[key] = {"cpu": 0, "mem": 0, "c": 0, "dt": ts}
            buckets[key]["cpu"] += (cpu or 0)
            buckets[key]["mem"] += (mem or 0)
            buckets[key]["c"] += 1
            
        trends = []
        for k in sorted(buckets.keys()):
            b = buckets[k]
            label = b["dt"].strftime("%b %d") if group_by_day else b["dt"].strftime("%H:00")
            trends.append({
                "time": label,
                "cpu": round(b["cpu"] / b["c"], 1),
                "mem": round(b["mem"] / b["c"], 1),
                "full_date": k
            })

        # 4. Threats (MongoDB) -- Resilient
        threats = {"total": 0, "byType": [], "trend": []}
        try:
            db_mongo = mongo["watchsec"]
            events_collection = db_mongo["events"]
            
            # Aggregation: Count by Type
            pipeline_type = [
                {"$match": {"Timestamp": {"$gte": start_dt, "$lte": end_dt}}},
                {"$group": {"_id": "$Type", "count": {"$sum": 1}}}
            ]
            cursor = events_collection.aggregate(pipeline_type)
            type_counts = await cursor.to_list(length=100)
            
            total_threats = sum(doc["count"] for doc in type_counts)
            by_type = [{"type": doc["_id"], "count": doc["count"]} for doc in type_counts]
            
            # Aggregation: Trend
            # Mongo group by date operators
            format_str = "%Y-%m-%d" if group_by_day else "%Y-%m-%d %H"
            pipeline_trend = [
                {"$match": {"Timestamp": {"$gte": start_dt, "$lte": end_dt}}},
                {"$group": {
                    "_id": {"$dateToString": {"format": format_str, "date": "$Timestamp"}},
                    "count": {"$sum": 1}
                }},
                {"$sort": {"_id": 1}}
            ]
            cursor_trend = events_collection.aggregate(pipeline_trend)
            trend_docs = await cursor_trend.to_list(length=100)
            
            # Format nicely
            threat_trend = []
            for doc in trend_docs:
                # Basic formatting, could be improved
                lbl = doc["_id"]
                if not group_by_day and " " in lbl: lbl = lbl.split(" ")[1] + ":00"
                threat_trend.append({"time": lbl, "count": doc["count"]})

            threats = {
                "total": total_threats,
                "byType": by_type,
                "trend": threat_trend
            }
        except Exception as e:
            print(f"[Dashboard] MongoDB Threats Error: {e}")

        # 5. Recent Logs
        recent_logs = []
        try:
             # Basic find in range
            cursor_logs = events_collection.find({"Timestamp": {"$gte": start_dt, "$lte": end_dt}}).sort("Timestamp", -1).limit(10)
            recent_docs = await cursor_logs.to_list(length=10)
            for doc in recent_docs:
                recent_logs.append({
                    "type": doc.get("Type", "Unknown"),
                    "details": doc.get("Details", ""),
                    "timestamp": doc.get("Timestamp").isoformat() if isinstance(doc.get("Timestamp"), datetime) else str(doc.get("Timestamp")),
                    "agentId": doc.get("AgentId", "Unknown")
                })
        except: pass

        # 6. Risky Assets
        risky_assets_data = []
        try:
            pipeline_risky = [
                {"$match": {"Timestamp": {"$gte": start_dt, "$lte": end_dt}}}, 
                {"$group": {"_id": "$AgentId", "threatCount": {"$sum": 1}}},
                {"$sort": {"threatCount": -1}},
                {"$limit": 5}
            ]
            cursor_risky = events_collection.aggregate(pipeline_risky)
            risky_docs = await cursor_risky.to_list(length=5)
            for doc in risky_docs:
                 if doc["_id"]: risky_assets_data.append({"agentId": doc["_id"], "threatCount": doc["threatCount"]})
        except: pass

        # 7. Productivity (Approx)
        offline_ratio = (offline_agents / total_agents) if total_agents > 0 else 0
        penalty_offline = offline_ratio * 100 * 0.5
        # Scale threats by time window to avoid "0 score" just because we looked at a year of data
        # Normalize threats per day
        days = max(1, total_hours / 24)
        threats_per_day = total_threats / days
        penalty_threats = min(50, threats_per_day * 2) 
        score = max(0, min(100, 100 - penalty_offline - penalty_threats))

        # 8. Network (Stub)
        net_in = round(online_agents * 0.5, 1)
        net_out = round(online_agents * 0.2, 1) 

        return {
            "agents": {"total": total_agents, "online": online_agents, "offline": offline_agents},
            "resources": {
                "avgCpu": round(avg_cpu, 1), 
                "avgMem": round(avg_mem, 1), 
                "trend": trends 
            },
            "threats": threats,
            "recentLogs": recent_logs,
            "network": {"inboundMbps": net_in, "outboundMbps": net_out, "activeConnections": online_agents * 4},
            "riskyAssets": risky_assets_data,
            "productivity": {"globalScore": int(score)}
        }
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise e

@router.get("/dashboard/topology")
async def get_network_topology(
    tenantId: Optional[int] = None, 
    db: AsyncSession = Depends(get_db),
    current_user: "User" = Depends(get_current_user)
):
    # Fetch all agents to build a Star Topology (Central Server -> Agents)
    # This replaces the static hardcoded list
    q = select(Agent)
    if tenantId: q = q.where(Agent.TenantId == tenantId)
    res = await db.execute(q)
    agents = res.scalars().all()
    
    topology = []
    
    # Add a central node manually (The WatchSec Server)
    topology.append({
        "agentId": "Control-Server",
        "localIp": "192.168.1.5", # Or dynamic server IP
        "gateway": "192.168.1.1",
        "lastSeen": datetime.utcnow().isoformat(),
        "status": "Online",
        "type": "server"
    })
    
    for a in agents:
        status = "Offline"
        if a.LastSeen:
            if (datetime.utcnow() - a.LastSeen).total_seconds() < 300:
                status = "Online"
        
        topology.append({
            "agentId": a.Hostname or a.AgentId,
            "localIp": a.LocalIp or "Unknown",
            "gateway": "192.168.1.1", # Simplification: Assuming flat network for now
            "lastSeen": a.LastSeen.isoformat() if a.LastSeen else "",
            "status": status,
             "type": "agent"
        })
    
    # If empty, return at least empty list, handled by frontend
    return topology

