from fastapi import APIRouter, Depends # type: ignore
from fastapi.responses import JSONResponse # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession # type: ignore
from sqlalchemy.future import select # type: ignore
from sqlalchemy import desc, func, case # type: ignore
from typing import List, Optional # type: ignore
from datetime import datetime, timedelta # type: ignore

from ..db.session import get_db # type: ignore
from ..db.models import AgentReportEntity, Agent, User, EventLog, ActivityLog as ActivityLogModel # type: ignore
from .deps import get_current_user # type: ignore

router = APIRouter()

@router.get("/status")
async def get_dashboard_status(
    tenantId: Optional[int] = None, 
    db: AsyncSession = Depends(get_db),
    current_user: "User" = Depends(get_current_user)
):
    try:
        if current_user.Role != "SuperAdmin":
            tenantId = current_user.TenantId

        # [REFACTORED] Use SQL to get the LATEST report for each agent in one go.
        # This prevents loading 100k+ reports into Python memory.
        
        # 1. Fetch Agents
        agent_query = select(Agent)
        try:
            agent_query = agent_query.where(Agent.IsPendingUninstall == False)
        except Exception:
            pass # Handle missing column gracefully

        if tenantId:
            agent_query = agent_query.where(Agent.TenantId == tenantId)
        
        agent_result = await db.execute(agent_query)
        agents = agent_result.scalars().all()
        agents_map = {a.AgentId: a for a in agents}
        
        if not agents:
            return []

        # 2. Optimized Subquery to get Max ID per Agent (simplest way for latest row)
        threshold = datetime.utcnow() - timedelta(hours=24)
        
        subq = select(
            AgentReportEntity.AgentId,
            func.max(AgentReportEntity.Id).label("max_id")
        ).where(AgentReportEntity.Timestamp >= threshold).group_by(AgentReportEntity.AgentId)
        
        if tenantId:
            subq = subq.where(AgentReportEntity.TenantId == tenantId)
        
        # Now join back to get full row
        report_subq = subq.subquery()
        latest_reports_query = select(AgentReportEntity).join(
            report_subq, 
            AgentReportEntity.Id == report_subq.c.max_id
        )
        
        res = await db.execute(latest_reports_query)
        latest_reports = res.scalars().all()
        reports_map = {r.AgentId: r for r in latest_reports}

        now = datetime.utcnow()
        results = []
        for agent_id, agent in agents_map.items():
            report = reports_map.get(agent_id)
            
            status = "Offline"
            cpu = 0
            mem = 0
            ts = agent.LastSeen or now
            
            if report:
                cpu = report.CpuUsage
                mem = report.MemoryUsage
                ts = report.Timestamp
                if (now - ts).total_seconds() < 120:
                    status = "Online"
            elif agent.LastSeen and (now - agent.LastSeen).total_seconds() < 120:
                # Fallback to agent table metadata if no report in 24h but heartbeat is fresh
                status = "Online"
                cpu = agent.CpuUsage
                mem = agent.MemoryUsage
                ts = agent.LastSeen

            results.append({
                "id": agent.Id,
                "agentId": agent_id,
                "status": status,
                "cpuUsage": cpu,
                "memoryUsage": mem,
                "timestamp": ts.isoformat() + "Z",
                "hostname": agent.Hostname or "Unknown",
                "version": agent.Version,
                "latitude": agent.Latitude,
                "longitude": agent.Longitude,
                "hardwareJson": agent.HardwareJson,
                "powerStatusJson": agent.PowerStatusJson
            })

        return results
    except Exception as e:
        import traceback # type: ignore
        traceback.print_exc()
        return JSONResponse(status_code=500, content={"detail": str(e), "trace": traceback.format_exc()})

@router.get("/dashboard/stats")
async def get_dashboard_stats(
    hours: int = 24,
    from_date: Optional[str] = None, # type: ignore
    to_date: Optional[str] = None,
    tenantId: Optional[int] = None, 
    db: AsyncSession = Depends(get_db),
    current_user: "User" = Depends(get_current_user)
):
    if current_user.Role != "SuperAdmin":
        tenantId = current_user.TenantId

    # [NEW] Fetch Plan for Data Filtering
    from ..core.constants import FEATURE_TIERS, PLAN_LEVELS # type: ignore
    plan_name = "Starter"
    plan_level = 1
    
    if tenantId:
        from ..db.models import Tenant # type: ignore
        t_res = await db.execute(select(Tenant).where(Tenant.Id == tenantId))
        tenant_obj = t_res.scalars().first()
        if tenant_obj:
            plan_name = tenant_obj.Plan
            plan_level = PLAN_LEVELS.get(plan_name, 1)

    # Helper to check if a specific log type is allowed for this plan
    def is_type_allowed(log_type):
        log_type_str = str(log_type).lower()
        # Only filter out explicitly enterprise-tier feature log types
        if plan_level < 3:  # Not Enterprise
            enterprise_only = ["shadow", "speech", "remoteshell", "mail", "livestream", "live_stream"]
            for key in enterprise_only:
                if key in log_type_str.replace("_", ""):
                    return False
        if plan_level < 2:  # Not Professional
            pro_only = ["keystrokes", "keylogger", "clipboard"]
            for key in pro_only:
                if key in log_type_str:
                    return False
        return True

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
    
    tenant_agent_ids = []
    try:
        if tenantId:
            res_agents = await db.execute(select(Agent.AgentId).where(Agent.TenantId == tenantId))
            tenant_agent_ids = res_agents.scalars().all()
            if not tenant_agent_ids:
                tenant_agent_ids = ["__dummy_none__"]
    except Exception:
        pass
    try:
        total_agents = 0
        online_agents = 0
        
        # 1. Agent Stats
        q_total = select(func.count(Agent.Id))
        try:
             q_total = q_total.where(Agent.IsPendingUninstall == False)
        except Exception:
             pass

        if tenantId: q_total = q_total.where(Agent.TenantId == tenantId)
        total_res = await db.execute(q_total)
        total_agents = total_res.scalar() or 0
        
        threshold_online = now_utc - timedelta(minutes=2)
        
        # [FIX] Use Agent.LastSeen directly (updated every heartbeat) and sum network stats
        q_online = select(
            func.count(Agent.Id),
            func.sum(Agent.NetworkInMbps),
            func.sum(Agent.NetworkOutMbps)
        ).where(Agent.LastSeen >= threshold_online)
        
        try:
            q_online = q_online.where(Agent.IsPendingUninstall == False)
        except Exception:
            pass
            
        if tenantId: q_online = q_online.where(Agent.TenantId == tenantId)
        online_res = await db.execute(q_online)
        online_row = online_res.one_or_none()
        online_agents = online_row[0] if online_row and online_row[0] else 0
        inbound_mbps = round(float(online_row[1] or 0), 2) if online_row else 0
        outbound_mbps = round(float(online_row[2] or 0), 2) if online_row else 0
        
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

        # 3. Resource Trend (Optimized: SQL-Level Bucketing)
        group_by_day = total_hours > 48
        
        from ..db.session import settings # type: ignore
        is_sqlite = settings.DATABASE_URL.startswith("sqlite")
        
        if is_sqlite:
            fmt = '%Y-%m-%d' if group_by_day else '%Y-%m-%d %H:00'
            time_expr = func.strftime(fmt, AgentReportEntity.Timestamp)
        else:
            fmt = '%Y-%m-%d' if group_by_day else '%Y-%m-%d %H:00'
            time_expr = func.date_format(AgentReportEntity.Timestamp, fmt)

        q_trend = select(
            time_expr.label("time_bucket"),
            func.avg(AgentReportEntity.CpuUsage).label("cpu"),
            func.avg(AgentReportEntity.MemoryUsage).label("mem")
        ).where(AgentReportEntity.Timestamp >= start_dt)\
         .where(AgentReportEntity.Timestamp <= end_dt)\
         .group_by(time_expr)\
         .order_by(time_expr)
        
        if tenantId: q_trend = q_trend.where(AgentReportEntity.TenantId == tenantId)
        
        trend_res = await db.execute(q_trend) 
        items = trend_res.all()
        
        trends = []
        for bucket, cpu, mem in items:
            try:
                # If group_by_day is true, bucket is 'YYYY-MM-DD'. Else 'YYYY-MM-DD HH:00'
                dt_format = "%Y-%m-%d" if group_by_day else "%Y-%m-%d %H:00"
                dt = datetime.strptime(str(bucket), dt_format)
                label = dt.strftime("%b %d") if group_by_day else dt.strftime("%H:00")
            except:
                label = str(bucket)
                
            trends.append({
                "time": label,
                "cpu": round(float(cpu or 0), 1),
                "mem": round(float(mem or 0), 1),
                "full_date": str(bucket)
            })

        # 4. Threats
        threats = {"total": 0, "byType": [], "trend": []}
        try:
            q_type = select(EventLog.Type, func.count(EventLog.Id))
            if tenantId:
                q_type = q_type.where(EventLog.AgentId.in_(tenant_agent_ids))
            
            q_type = q_type.where((EventLog.Timestamp >= start_dt) & (EventLog.Timestamp <= end_dt)).group_by(EventLog.Type)
            
            res_type = await db.execute(q_type)
            type_counts = res_type.all()
            
            # [NEW] Filter Threats by Plan
            filtered_counts = []
            for t, c in type_counts:
                if is_type_allowed(t):
                    filtered_counts.append((t, c))
            
            total_threats = sum(c for _, c in filtered_counts)
            by_type = [{"type": t, "count": c} for t, c in filtered_counts]
            
            # Threat Trend (SQL-Level Bucketing)
            if is_sqlite:
                evt_time_expr = func.strftime(fmt, EventLog.Timestamp)
            else:
                evt_time_expr = func.date_format(EventLog.Timestamp, fmt)
                
            q_evt_trend = select(evt_time_expr.label("time_bucket"), func.count(EventLog.Id).label("c"))
            if tenantId:
                q_evt_trend = q_evt_trend.where(EventLog.AgentId.in_(tenant_agent_ids))
            q_evt_trend = q_evt_trend.where((EventLog.Timestamp >= start_dt) & (EventLog.Timestamp <= end_dt))
            q_evt_trend = q_evt_trend.group_by(evt_time_expr).order_by(evt_time_expr)
            
            res_evt_trend = await db.execute(q_evt_trend)
            trend_items = res_evt_trend.all()
            
            threat_trend = []
            for bucket, count in trend_items:
                threat_trend.append({"time": str(bucket), "count": count})

            threats = {
                "total": total_threats,
                "total24h": total_threats,
                "byType": by_type,
                "trend": threat_trend
            }
        except Exception as e:
            print(f"[Dashboard] Threats Error: {e}")

        # 5. Recent Logs
        recent_logs = []
        try:
            # Fetch recent EventLog rows
            q_evts = select(EventLog).order_by(EventLog.Timestamp.desc()).limit(20)
            if tenantId:
                q_evts = q_evts.where(EventLog.AgentId.in_(tenant_agent_ids))
            res_evts = await db.execute(q_evts)
            evt_docs = res_evts.scalars().all()
            
            # Fetch recent ActivityLog rows
            q_acts = select(ActivityLogModel).order_by(ActivityLogModel.Timestamp.desc()).limit(20)
            if tenantId:
                q_acts = q_acts.where(ActivityLogModel.TenantId == tenantId)
            res_acts = await db.execute(q_acts)
            act_docs = res_acts.scalars().all()
            
            merged = []
            for doc in evt_docs:
                if not is_type_allowed(doc.Type): continue
                merged.append({
                    "type": doc.Type,
                    "details": doc.Details or "Security Incident",
                    "timestamp": doc.Timestamp,
                    "agentId": doc.AgentId
                })
                
            for doc in act_docs:
                if not is_type_allowed(doc.ActivityType): continue
                merged.append({
                    "type": doc.ActivityType,
                    "details": f"{doc.ProcessName or ''} {doc.WindowTitle or ''}".strip(),
                    "timestamp": doc.Timestamp,
                    "agentId": doc.AgentId
                })
                
            # Sort by timestamp desc
            merged.sort(key=lambda x: x["timestamp"], reverse=True)
            
            for item in merged[:15]:
                recent_logs.append({
                    "type": item["type"],
                    "details": item["details"],
                    "timestamp": item["timestamp"].isoformat(),
                    "agentId": item["agentId"]
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
        fleet_score = max(0, min(100, 100 - (offline_ratio * 50)))
        
        # [NEW] Productivity Breakdown (SQL Based)
        # Summing categories over the requested range for the tenant
        productivity_breakdown = []
        try:
            from ..db.models import ActivityLog # type: ignore
            # Get category counts
            q_prod = select(ActivityLog.Category, func.count(ActivityLog.Id)).where(
                (ActivityLog.Timestamp >= start_dt) & (ActivityLog.Timestamp <= end_dt)
            )
            if tenantId:
                q_prod = q_prod.where(ActivityLog.TenantId == tenantId)
            
            q_prod = q_prod.group_by(ActivityLog.Category)
            res_prod = await db.execute(q_prod)
            prod_items = res_prod.all()
            
            # Fallback to all-time data if 24h is empty
            if not prod_items:
                q_prod_fallback = select(ActivityLog.Category, func.count(ActivityLog.Id))
                if tenantId:
                    q_prod_fallback = q_prod_fallback.where(ActivityLog.TenantId == tenantId)
                q_prod_fallback = q_prod_fallback.group_by(ActivityLog.Category)
                res_prod = await db.execute(q_prod_fallback)
                prod_items = res_prod.all()
            
            for cat, count in prod_items:
                cat_name = cat or "Neutral"
                color = "#6366F1" # Indigo (Neutral)
                if cat_name in ["High", "Security", "Risk", "Critical"]: color = "#EF4444" # Red
                elif cat_name in ["Unproductive", "Social", "Entertainment"]: color = "#F59E0B" # Amber
                elif cat_name in ["Productive", "Work", "Dev", "Office"]: color = "#10B981" # Emerald
                
                productivity_breakdown.append({
                    "name": cat_name,
                    "value": count,
                    "color": color
                })
        except Exception as e:
            print(f"[Dashboard] Productivity Breakdown Error: {e}")

        # 8. Network (Real Data Only)
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
                "inboundMbps": inbound_mbps, 
                "outboundMbps": outbound_mbps, 
                "activeConnections": online_agents
            },
            "riskyAssets": risky_assets_data,
            "productivity": {
                "globalScore": int(fleet_score),
                "breakdown": productivity_breakdown
            }
        }
    except Exception as e:
        import traceback # type: ignore
        traceback.print_exc()
        return JSONResponse(status_code=500, content={"detail": str(e), "trace": traceback.format_exc()})

@router.get("/dashboard/topology")
async def get_network_topology(
    tenantId: Optional[int] = None, 
    db: AsyncSession = Depends(get_db),
    current_user: "User" = Depends(get_current_user)
):
    if current_user.Role != "SuperAdmin":
        tenantId = current_user.TenantId
        
    # Fetch all agents to build a Star Topology (Central Server -> Agents)
    # This replaces the static hardcoded list
    q = select(Agent).where(Agent.IsPendingUninstall == False)
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

