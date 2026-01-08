from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import desc, func, case
from typing import List, Optional
from datetime import datetime, timedelta

from ..db.session import get_db
from ..db.models import AgentReportEntity, Agent, User, EventLog, ActivityLog as ActivityLogModel
from .deps import get_current_user

router = APIRouter()

@router.get("/status")
async def get_dashboard_status(
    tenantId: Optional[int] = None, 
    db: AsyncSession = Depends(get_db),
    current_user: "User" = Depends(get_current_user)
):
    try:
        # Enforce Tenant Isolation
        if current_user.Role != "SuperAdmin":
            tenantId = current_user.TenantId

        # 1. Fetch Agents for metadata
        agent_query = select(Agent)
        if tenantId:
           agent_query = agent_query.where(Agent.TenantId == tenantId)
        agent_result = await db.execute(agent_query)
        agents_map = {a.AgentId: a for a in agent_result.scalars().all()}

        # 2. Fetch Latest Reports for Status Calculation
        query = select(AgentReportEntity).order_by(desc(AgentReportEntity.Timestamp))
        if tenantId:
            query = query.where(AgentReportEntity.TenantId == tenantId)
        
        threshold = datetime.utcnow() - timedelta(hours=24)
        query = query.where(AgentReportEntity.Timestamp >= threshold)

        result = await db.execute(query)
        all_reports = result.scalars().all()

        latest = {}
        
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

        for r in all_reports:
            if r.AgentId in latest and latest[r.AgentId].get("_processed"):
                 continue
            
            computed_status = "Online" if (datetime.utcnow() - r.Timestamp).total_seconds() < 120 else "Offline"
            
            if r.AgentId not in latest:
                 latest[r.AgentId] = {} 

            ts_str = r.Timestamp.isoformat()
            if not ts_str.endswith("Z"): ts_str += "Z"

            latest[r.AgentId].update({
                "agentId": r.AgentId,
                "status": computed_status,
                "cpuUsage": r.CpuUsage,
                "memoryUsage": r.MemoryUsage,
                "timestamp": ts_str,
                "hostname": agents_map[r.AgentId].Hostname if r.AgentId in agents_map else "Unknown",
                "_processed": True 
            })

        for v in latest.values():
            if "_processed" in v: del v["_processed"]

        return list(latest.values())
    except Exception as e:
        import traceback
        traceback.print_exc()
        return JSONResponse(status_code=500, content={"detail": str(e), "trace": traceback.format_exc()})

@router.get("/dashboard/stats")
async def get_dashboard_stats(
    hours: int = 24,
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
    tenantId: Optional[int] = None, 
    db: AsyncSession = Depends(get_db),
    current_user: "User" = Depends(get_current_user)
):
    # Enforce Tenant Isolation
    if current_user.Role != "SuperAdmin":
        tenantId = current_user.TenantId

    # 0. Time Range Logic
    now_utc = datetime.utcnow()
    
    if from_date:
        try:
            start_dt = datetime.fromisoformat(from_date.replace('Z', '+00:00'))
        except:
            start_dt = now_utc - timedelta(hours=hours)
    else:
        start_dt = now_utc - timedelta(hours=hours)

    if to_date:
        try:
            end_dt = datetime.fromisoformat(to_date.replace('Z', '+00:00'))
        except:
            end_dt = now_utc
    else:
        end_dt = now_utc

    if start_dt.tzinfo is not None: start_dt = start_dt.replace(tzinfo=None)
    if end_dt.tzinfo is not None: end_dt = end_dt.replace(tzinfo=None)

    total_hours = (end_dt - start_dt).total_seconds() / 3600
    
    try:
        total_agents = 0
        online_agents = 0
        
        # 1. Agent Stats
        q_total = select(func.count(Agent.Id))
        if tenantId: q_total = q_total.where(Agent.TenantId == tenantId)
        total_res = await db.execute(q_total)
        total_agents = total_res.scalar() or 0
        
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
        
        trend_res = await db.execute(q_trend.limit(5000)) 
        items = trend_res.all()
        
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

        # 4. Threats
        threats = {"total": 0, "byType": [], "trend": []}
        # Note: EventLog doesn't strictly have TenantId column in some versions, but we should join or filter if possible.
        # Assuming AgentId is the link. To strictly filter by Tenant, we'd need to join Agents table (or add TenantId to EventLog).
        # For now, to be safe and given schema, we rely on AgentId match if we can, BUT EventLog in schema didn't show TenantId.
        # FIX: We must filter EventLog by joining Agent table.
        try:
            q_type = select(EventLog.Type, func.count(EventLog.Id))
            if tenantId:
                q_type = q_type.join(Agent, Agent.AgentId == EventLog.AgentId).where(Agent.TenantId == tenantId)
            
            q_type = q_type.where((EventLog.Timestamp >= start_dt) & (EventLog.Timestamp <= end_dt)).group_by(EventLog.Type)
            
            res_type = await db.execute(q_type)
            type_counts = res_type.all()
            
            total_threats = sum(c for _, c in type_counts)
            by_type = [{"type": t, "count": c} for t, c in type_counts]
            
            q_trend = select(EventLog.Timestamp)
            if tenantId:
                q_trend = q_trend.join(Agent, Agent.AgentId == EventLog.AgentId).where(Agent.TenantId == tenantId)
            q_trend = q_trend.where((EventLog.Timestamp >= start_dt) & (EventLog.Timestamp <= end_dt)).order_by(EventLog.Timestamp)
            
            res_trend = await db.execute(q_trend)
            trend_items = res_trend.scalars().all()
            
            format_str = "%Y-%m-%d" if group_by_day else "%Y-%m-%d %H:00"
            trend_buckets = {}
            for ts in trend_items:
                key = ts.strftime(format_str)
                trend_buckets[key] = trend_buckets.get(key, 0) + 1
            threat_trend = [{"time": k, "count": v} for k, v in sorted(trend_buckets.items())]

            threats = {
                "total": total_threats,
                "byType": by_type,
                "trend": threat_trend
            }
        except Exception as e:
            print(f"[Dashboard] Threats Error: {e}")

        # 5. Recent Logs
        recent_logs = []
        try:
            q_logs = select(ActivityLogModel).where(
                (ActivityLogModel.Timestamp >= start_dt) & (ActivityLogModel.Timestamp <= end_dt)
            ).order_by(ActivityLogModel.Timestamp.desc()).limit(10)
            
            if tenantId:
                q_logs = q_logs.where(ActivityLogModel.TenantId == tenantId)
                
            res_logs = await db.execute(q_logs)
            log_docs = res_logs.scalars().all()
            
            for doc in log_docs:
                recent_logs.append({
                    "type": doc.ActivityType,
                    "details": f"{doc.ProcessName or ''} {doc.WindowTitle or ''}",
                    "timestamp": doc.Timestamp.isoformat(),
                    "agentId": doc.AgentId
                })
        except Exception as e: 
             print(f"[Dashboard] Recent Logs Error: {e}")

        # 6. Risky Assets
        risky_assets_data = []
        try:
            q_risk = select(ActivityLogModel.AgentId, func.count(ActivityLogModel.Id).label("count"))\
                .where((ActivityLogModel.Timestamp >= start_dt) & (ActivityLogModel.Timestamp <= end_dt))\
                .where(ActivityLogModel.RiskLevel == "High")\
                .group_by(ActivityLogModel.AgentId)\
                .order_by(desc("count"))\
                .limit(5)
                
            if tenantId:
                q_risk = q_risk.where(ActivityLogModel.TenantId == tenantId)

            res_risk = await db.execute(q_risk)
            for agent_id, count in res_risk.all():
                 risky_assets_data.append({"agentId": agent_id, "threatCount": count})
        except Exception as e:
            print(f"[Dashboard] Risky Assets Error: {e}")

        # 7. Productivity
        offline_ratio = (offline_agents / total_agents) if total_agents > 0 else 0
        score = max(0, min(100, 100 - (offline_ratio * 50)))

        # 8. Network (Real Data Only)
        # We generally do not have bandwidth data unless agents send it. 
        # Using 0 for Mbps to indicate 'active but unknown bandwidth' or simply omitting if UI handles it.
        # But for 'activeConnections', we use online_agents count.
        
        return {
            "agents": {"total": total_agents, "online": online_agents, "offline": offline_agents},
            "resources": {
                "avgCpu": round(avg_cpu, 1), 
                "avgMem": round(avg_mem, 1), 
                "trend": trends 
            },
            "threats": threats,
            "recentLogs": recent_logs,
            "network": {
                "inboundMbps": 0, 
                "outboundMbps": 0, 
                "activeConnections": online_agents
            },
            "riskyAssets": risky_assets_data,
            "productivity": {"globalScore": int(score)}
        }
    except Exception as e:
        import traceback
        traceback.print_exc()
        return JSONResponse(status_code=500, content={"detail": str(e), "trace": traceback.format_exc()})

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

