from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import desc
from typing import List, Optional

from ..db.session import get_db
from ..db.models import AgentReportEntity

router = APIRouter()

from datetime import datetime, timedelta
from sqlalchemy import func

@router.get("/status")
async def get_dashboard_status(tenantId: Optional[int] = None, db: AsyncSession = Depends(get_db)):
    # Fetch Real Reports
    query = select(AgentReportEntity).order_by(desc(AgentReportEntity.Timestamp))
    if tenantId:
        query = query.where(AgentReportEntity.TenantId == tenantId)
    
    result = await db.execute(query)
    all_reports = result.scalars().all()

    # Group By AgentId (Latest Only)
    latest = {}
    for r in all_reports:
        if r.AgentId not in latest:
            latest[r.AgentId] = {
                "agentId": r.AgentId,
                "status": r.Status,
                "cpuUsage": r.CpuUsage,
                "memoryUsage": r.MemoryUsage,
                "timestamp": r.Timestamp,
                "latitude": 0.0, # Default if missing
                "longitude": 0.0 
            }

    # If we have real agents, try to fetch their real location from Agent table
    # (Skipping for now to prioritize the "Demo" view requested by user)
    
    # DEMO MODE: If fewer than 5 agents, inject Mock Agents so the Map looks cool
    if len(latest) < 5:
        mock_locations = [
            {"id": "Server-US-East", "lat": 40.7128, "lon": -74.0060, "status": "Running"}, # NY
            {"id": "Workstation-London", "lat": 51.5074, "lon": -0.1278, "status": "Running"}, # London
            {"id": "Database-sg", "lat": 1.3521, "lon": 103.8198, "status": "Running"}, # Singapore
            {"id": "Laptop-Tokyo", "lat": 35.6762, "lon": 139.6503, "status": "Offline"}, # Tokyo
            {"id": "Backup-Sydney", "lat": -33.8688, "lon": 151.2093, "status": "Running"} # Sydney
        ]
        
        import random
        for m in mock_locations:
            if m["id"] not in latest:
                latest[m["id"]] = {
                    "agentId": m["id"],
                    "status": m["status"],
                    "cpuUsage": round(random.uniform(10, 60), 1),
                    "memoryUsage": round(random.uniform(20, 80), 1),
                    "timestamp": datetime.utcnow(),
                    "latitude": m["lat"],
                    "longitude": m["lon"]
                }
    
    return list(latest.values())

@router.get("/dashboard/stats")
async def get_dashboard_stats(hours: int = 24, tenantId: Optional[int] = None, db: AsyncSession = Depends(get_db)):
    # 1. Agent Stats
    total_agents = 0
    online_agents = 0
    offline_agents = 0
    
    # Mocking Agent check for demo speed (or query Agent table)
    # real_agents = await db.execute(select(Agent))
    # ... logic ...
    
    # Using the reports to estimate online status (< 5 mins)
    query_reports = select(AgentReportEntity).order_by(desc(AgentReportEntity.Timestamp))
    if tenantId:
        query_reports = query_reports.where(AgentReportEntity.TenantId == tenantId)
    result_reports = await db.execute(query_reports)
    reports = result_reports.scalars().all()
    
    latest_reports = {}
    for r in reports:
        if r.AgentId not in latest_reports:
            latest_reports[r.AgentId] = r
            
    total_agents = len(latest_reports)
    now = datetime.utcnow()
    for agent_id, r in latest_reports.items():
        if (now - r.Timestamp).total_seconds() < 300: # 5 mins
            online_agents += 1
        else:
            offline_agents += 1
            
    # 2. Resources (Avg of latest)
    avg_cpu = 0
    avg_mem = 0
    start_cpu = 15.0
    start_mem = 30.0
    
    if total_agents > 0:
        avg_cpu = sum(r.CpuUsage for r in latest_reports.values()) / total_agents
        avg_mem = sum(r.MemoryUsage for r in latest_reports.values()) / total_agents
        
    # Generate 24h Trend Data (Mock logic to make charts stream nicely)
    # in Production, query: SELECT avg(Cpu), Hour FROM Archive ...
    trends = []
    import random
    current_time = datetime.utcnow()
    for i in range(24, 0, -1):
        t_time = current_time - timedelta(hours=i)
        trends.append({
            "time": t_time.strftime("%H:00"),
            "cpu": round(max(5, min(95, start_cpu + random.uniform(-10, 15))), 1),
            "mem": round(max(10, min(90, start_mem + random.uniform(-5, 10))), 1)
        })

    # 3. Threats (Dummy / Mock for visualization support)
    # In prod: query SecurityEventLog table
    threat_trend = []
    for i in range(24, 0, -1):
        threat_trend.append({
            "hour": i,
            "count": int(random.expovariate(0.5)) # Poisson-ish distribution
        })

    threats = {
        "total24h": sum(t["count"] for t in threat_trend),
        "byType": [
             {"type": "Malware", "count": 12},
             {"type": "Phishing", "count": 8},
             {"type": "Intrusion", "count": 4},
             {"type": "DLP Violation", "count": 2}
        ],
        "trend": threat_trend
    }


    
    # 4. Recent Logs
    recent_logs = [
        {"type": "System", "details": "Backup completed successfully", "timestamp": str(datetime.utcnow()), "agentId": "Server-01"},
        {"type": "Security", "details": "Brute force attempt blocked", "timestamp": str(datetime.utcnow() - timedelta(minutes=10)), "agentId": "Workstation-05"},
        {"type": "Network", "details": "High outbound traffic detected", "timestamp": str(datetime.utcnow() - timedelta(minutes=25)), "agentId": "Gateway-01"},
        {"type": "System", "details": "Agent auto-update successful", "timestamp": str(datetime.utcnow() - timedelta(minutes=40)), "agentId": "Laptop-HR-02"},
         {"type": "Threat", "details": "Malicious payload quarantined", "timestamp": str(datetime.utcnow() - timedelta(minutes=120)), "agentId": "Workstation-Dev-09"}
    ]
    
    # 5. Global Productivity (Mock)
    global_score = 87
    if online_agents > 5: global_score = 92
    
    # 6. Risky Assets (Mock)
    risky_assets = [
        {"agentId": "Workstation-Dev-09", "threatCount": 5},
        {"agentId": "Laptop-Finance-01", "threatCount": 3}
    ]
    
    return {
        "agents": {"total": total_agents, "online": online_agents, "offline": offline_agents},
        "resources": {
            "avgCpu": round(avg_cpu, 1), 
            "avgMem": round(avg_mem, 1), 
            "trend": trends 
        },
        "threats": threats,
        "recentLogs": recent_logs,
        "network": {"inboundMbps": round(random.uniform(10, 100),1), "outboundMbps": round(random.uniform(5, 50), 1), "activeConnections": 1240},
        "riskyAssets": risky_assets,
        "productivity": {"globalScore": global_score}
    }

@router.get("/dashboard/topology")
async def get_network_topology(tenantId: Optional[int] = None, db: AsyncSession = Depends(get_db)):
    # In production, query Agents table to get LocalIp and Gateway
    # For this demo, return a static/mock topology so the Graph renders
    
    topology = [
        {"agentId": "DESKTOP-HQ-01", "localIp": "192.168.1.10", "gateway": "192.168.1.1", "lastSeen": str(datetime.utcnow()), "status": "Online"},
        {"agentId": "DESKTOP-HQ-02", "localIp": "192.168.1.15", "gateway": "192.168.1.1", "lastSeen": str(datetime.utcnow()), "status": "Online"},
        {"agentId": "SERVER-DB-01", "localIp": "10.0.0.5", "gateway": "10.0.0.1", "lastSeen": str(datetime.utcnow()), "status": "Online"},
        {"agentId": "SERVER-WEB-01", "localIp": "10.0.0.6", "gateway": "10.0.0.1", "lastSeen": str(datetime.utcnow()), "status": "Online"},
        {"agentId": "GUEST-LAPTOP", "localIp": "172.16.0.45", "gateway": "172.16.0.1", "lastSeen": str(datetime.utcnow()), "status": "Offline"},
    ]
    
    return topology
