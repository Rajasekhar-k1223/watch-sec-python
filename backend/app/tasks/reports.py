"""
Celery Task: Report Scheduling
=================================
- Runs every minute (via beat schedule)
- Checks if each tenant's scheduled_time matches current UTC time
- Respects auto_enabled flag
- Sends to all configured emails
- Supports: daily / weekly / 15days / monthly frequencies
"""

from datetime import datetime, timedelta # type: ignore
import os # type: ignore
from sqlalchemy import select, update # type: ignore
from app.core.celery_app import celery_app # type: ignore
from app.db.session import AsyncSessionLocal # type: ignore
from app.db.models import Tenant, Agent, EventLog, ActivityLog, ReportFile # type: ignore
from app.services.excel_reports import ExcelReportService # type: ignore
from app.services.email_service import email_service # type: ignore
from app.api.report_downloads import create_download_url # type: ignore
import asyncio # type: ignore

MONITORIX_BASE_URL = "https://monitorix.co.in"

FREQUENCY_DAYS = {
    "daily":   1,
    "weekly":  7,
    "15days":  15,
    "monthly": 30,
}

FREQUENCY_LABELS = {
    "daily":   "Daily",
    "weekly":  "Weekly",
    "15days":  "15-Day",
    "monthly": "Monthly",
}


@celery_app.task(name="app.tasks.reports.send_tenant_reports")
def send_tenant_reports():
    """
    Runs every minute. Checks all tenants to see if their scheduled send time
    has been reached and auto_enabled is True.
    """
    loop = asyncio.get_event_loop()
    if loop.is_running():
        asyncio.ensure_future(_send_reports_async())
    else:
        loop.run_until_complete(_send_reports_async())


async def _send_reports_async():
    now = datetime.utcnow()
    current_time_str = now.strftime("%H:%M")  # e.g. "08:00"

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(Tenant))
        tenants = result.scalars().all()

        for tenant in tenants:
            cfg = tenant.ReportingConfigJson or {}

            # Skip if auto scheduling is not enabled
            if not cfg.get("auto_enabled", False):
                continue

            scheduled_time = cfg.get("scheduled_time", "08:00")  # HH:MM UTC
            frequency      = cfg.get("frequency", "weekly")
            emails         = cfg.get("emails", [])
            last_sent_str  = cfg.get("last_sent")

            # Only fire if current minute matches scheduled time
            if current_time_str != scheduled_time:
                # Debug log every 10 minutes to avoid spam, or just once per hour?
                # Actually, let's just log when it's NOT matching but auto_enabled is true
                if now.minute % 30 == 0: 
                    print(f"[Reports] Pending: {tenant.Name} scheduled for {scheduled_time} UTC (Current: {current_time_str})")
                continue

            print(f"[Reports] Time reached for {tenant.Name} ({scheduled_time}). Checking frequency...")

            # Check if we already sent within the required period
            days_required = FREQUENCY_DAYS.get(frequency, 7)
            if last_sent_str:
                last_sent = datetime.fromisoformat(last_sent_str)
                # Allow a small buffer (0.1 days) to avoid edge cases with exact minute matching
                if now - last_sent < timedelta(days=days_required - 0.1):
                    print(f"[Reports] Skipping {tenant.Name}: already sent {(now - last_sent).days}d ago (Freq: {frequency})")
                    continue

            if not emails:
                emails = [tenant.AdminEmail] if tenant.AdminEmail else []

            if not emails:
                print(f"[Reports] ❌ Skip {tenant.Name}: No recipients found.")
                continue

            print(f"[Reports] >>> Auto-sending {frequency} report to {tenant.Name} → {emails}")
            label = FREQUENCY_LABELS.get(frequency, "Scheduled")
            
            try:
                success = await _process_tenant_report_for_emails(session, tenant, days=days_required, timeframe_label=label, emails=emails)
                if success:
                    cfg_copy = dict(cfg)
                    cfg_copy["last_sent"] = now.isoformat()
                    await session.execute(
                        update(Tenant).where(Tenant.Id == tenant.Id).values(ReportingConfigJson=cfg_copy)
                    )
                    await session.commit()
                    print(f"[Reports] ✅ SUCCESS: Report sent for {tenant.Name}. Next run in {days_required} days.")
                else:
                    print(f"[Reports] ❌ FAILURE: Report generation failed for {tenant.Name}.")
            except Exception as e:
                print(f"[Reports] ❌ CRITICAL ERROR for {tenant.Name}: {e}")


async def _process_tenant_report_for_emails(session, tenant, days: int, timeframe_label: str, emails: list) -> bool:
    """
    Core report generation. Generates Excel, creates download link, sends to all emails.
    Called by both the Celery auto-scheduler and the manual send-now API.
    """
    # 1. Fetch agents
    agent_res = await session.execute(select(Agent).where(Agent.TenantId == tenant.Id))
    agents = agent_res.scalars().all()
    if not agents:
        print(f"[Reports] No agents for {tenant.Name}")
        return False

    agent_ids = [a.AgentId for a in agents]

    # 2. Fetch historical data first to determine Risk Level
    start_date = datetime.utcnow() - timedelta(days=days)

    event_res = await session.execute(
        select(EventLog).where(
            EventLog.AgentId.in_(agent_ids),
            EventLog.Timestamp >= start_date
        ).order_by(EventLog.Timestamp.desc())
    )
    events = event_res.scalars().all()
    events_data = [{
        "Timestamp":  e.Timestamp.isoformat(),
        "Agent ID":   e.AgentId,
        "Event Type": e.Type,
        "Details":    (e.Details or "")[:200]
    } for e in events]
    
    # Pre-compute risk per agent based on events
    agent_risks = {}
    for e in events:
        current_risk = agent_risks.get(e.AgentId, "Low")
        # Risk escalation ladder
        if e.Type in ["HighThreat", "MalwareDetected"]:
            agent_risks[e.AgentId] = "Critical"
        elif e.Type in ["SuspiciousOperation", "PolicyViolation", "UsbBlocked"]:
            if current_risk != "Critical":
                agent_risks[e.AgentId] = "High"
        elif e.Type in ["AgentOffline", "HighCpuUsage"]:
            if current_risk not in ["Critical", "High"]:
                agent_risks[e.AgentId] = "Medium"

    # 3. Build agent summary
    agents_data = []
    for agent in agents:
        status = "Online" if (datetime.utcnow() - agent.LastSeen) < timedelta(minutes=10) else "Offline"
        
        cpu = f"{agent.CpuUsage}%" if agent.CpuUsage else "0.0%"
        mem = f"{agent.MemoryUsage}%" if agent.MemoryUsage else "0.0%"
        os_version = agent.Version or "Unknown"
        
        # Grab computed risk or default to Low
        risk_level = agent_risks.get(agent.AgentId, "Low")
            
        agents_data.append({
            "AgentId":    agent.AgentId,
            "Hostname":   agent.Hostname,
            "Ip Address": agent.PublicIp or agent.LocalIp,
            "OS Versions": os_version,
            "Last seen":  agent.LastSeen.strftime("%Y-%m-%d %H:%M:%S"),
            "Cpu usage(%)": cpu,
            "Memory Usage(%)": mem,
            "Status":     status,
            "Risk Level": risk_level
        })

    activity_res = await session.execute(
        select(ActivityLog).where(
            ActivityLog.AgentId.in_(agent_ids),
            ActivityLog.Timestamp >= start_date
        ).order_by(ActivityLog.Timestamp.desc()).limit(1000)
    )
    activities = activity_res.scalars().all()
    activity_data = [{
        "Timestamp": a.Timestamp.isoformat(),
        "Agent ID":  a.AgentId,
        "Type":      a.ActivityType,
        "Process":   a.ProcessName,
        "Window":    a.WindowTitle,
        "Risk":      a.RiskLevel
    } for a in activities]

    # 4. Generate Excel file
    os.makedirs("/app/storage/reports", exist_ok=True)
    report_name = f"Monitorix_{timeframe_label}_Report_{tenant.Name}_{datetime.utcnow().strftime('%Y%m%d_%H%M')}.xlsx"
    report_path = f"/app/storage/reports/{report_name}"

    ExcelReportService.generate_tenant_report(
        tenant.Name, agents_data, report_path,
        events_data=events_data,
        activity_data=activity_data
    )
    print(f"[Reports] Excel generated: {report_path}")

    # 5. Create signed 7-day download link
    download_url = create_download_url(MONITORIX_BASE_URL, report_name)

    # [NEW] Cache Metadata in SQL
    try:
        new_file = ReportFile(
            TenantId=tenant.Id,
            Filename=report_name,
            Path=report_path,
            Size=os.path.getsize(report_path),
            DownloadUrl=download_url,
            GeneratedAt=datetime.utcnow()
        )
        session.add(new_file)
        await session.commit()
    except Exception as me:
        print(f"[Reports] Metadata cache error: {me}")

    # 6. Build HTML email
    subject = f"Monitorix {timeframe_label} Security Report — {tenant.Name} ({datetime.utcnow().strftime('%Y-%m-%d')})"
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>{subject}</title>
    </head>
    <body style="margin:0;padding:0;background-color:#f9f9f9;">
      <div style="font-family:Arial,sans-serif;max-width:600px;margin:20px auto;padding:0;background:#f9f9f9;">
        <div style="background:#1e2437;color:white;padding:20px 30px;border-radius:12px 12px 0 0;">
          <h1 style="margin:0;font-size:22px;">&#128202; Monitorix {timeframe_label} Report</h1>
          <p style="margin:5px 0 0;opacity:.7;font-size:13px;">{tenant.Name} &mdash; {datetime.utcnow().strftime('%Y-%m-%d')}</p>
        </div>
        <div style="background:white;padding:30px;border-radius:0 0 12px 12px;box-shadow:0 2px 8px rgba(0,0,0,.1);">
          <p style="color:#333;">Hello <b>{tenant.Name}</b>,</p>
          <p style="color:#555;">Your <b>{timeframe_label}</b> security report is ready — past <b>{days} days</b>, <b>{len(agents)}</b> agents monitored.</p>
          <table style="width:100%;border-collapse:collapse;margin:20px 0;">
            <tr style="background:#f0f4ff;"><td style="padding:10px 15px;font-weight:bold;color:#444;">Total Agents</td><td style="padding:10px 15px;">{len(agents)}</td></tr>
            <tr><td style="padding:10px 15px;font-weight:bold;color:#444;">Events Captured</td><td style="padding:10px 15px;">{len(events_data):,}</td></tr>
            <tr style="background:#f0f4ff;"><td style="padding:10px 15px;font-weight:bold;color:#444;">Activity Logs</td><td style="padding:10px 15px;">{len(activity_data):,}</td></tr>
            <tr><td style="padding:10px 15px;font-weight:bold;color:#444;">Report Period</td><td style="padding:10px 15px;">Past {days} days</td></tr>
          </table>
          <div style="text-align:center;margin:30px 0;">
            <a href="{download_url}" style="background:#4f46e5;color:white;text-decoration:none;padding:14px 32px;border-radius:8px;font-size:15px;font-weight:bold;display:inline-block;">
              &#11015; Download Excel Report (.xlsx)
            </a>
          </div>
          <p style="color:#888;font-size:12px;text-align:center;">Link valid for <b>7 days</b> &bull; Downloads from <b>monitorix.co.in</b></p>
        <div style="background:#f4f4f4;padding:20px;margin-top:30px;border-radius:8px;font-size:11px;color:#777;line-height:1.5;">
          <p style="margin:0;">
            <b>Why did I receive this?</b><br/>
            You are receiving this automated security report because your email is configured as a recipient in the Monitorix Report Settings for <b>{tenant.Name}</b>.
          </p>
          <p style="margin:10px 0 0;">
            <b>Monitorix Security Inc.</b><br/>
            Visit your <a href="{MONITORIX_BASE_URL}/reports" style="color:#4f46e5;text-decoration:none;">Reporting Dashboard</a> to manage your notification settings.
          </p>
        </div>
        <p style="color:#aaa;font-size:11px;margin-top:20px;text-align:center;">
          &copy; {datetime.utcnow().year} Monitorix Security. All rights reserved.
        </p>
      </div>
    </div>
    </body>
    </html>
    """
    # 7. Send to primary email and CC remaining
    if not emails:
        print("[Reports] ❌ No recipient emails configured.")
        return False
        
    primary_email = tenant.AdminEmail
    cc_emails = []
    
    if primary_email and primary_email in emails:
        cc_emails = [e for e in emails if e != primary_email]
    else:
        primary_email = emails[0]
        cc_emails = emails[1:]
        
    success = await email_service.send_email(
        to_email=primary_email,
        subject=subject,
        html_content=html_content,
        cc_emails=cc_emails if cc_emails else None
    )
    
    if success:
        print(f"[Reports] ✅ Sent to {primary_email} (CC: {cc_emails})")
        return True
    else:
        print(f"[Reports] ❌ Failed to send to {primary_email} (CC: {cc_emails})")
        return False


# Keep backward compat alias
async def _process_tenant_report(session, tenant, days=1):
    cfg = tenant.ReportingConfigJson or {}
    emails = cfg.get("emails", [tenant.AdminEmail] if tenant.AdminEmail else [])
    label = FREQUENCY_LABELS.get({1: "daily", 7: "weekly", 15: "15days", 30: "monthly"}.get(days, "weekly"), "Scheduled")
    return await _process_tenant_report_for_emails(session, tenant, days=days, timeframe_label=label, emails=emails)


@celery_app.task(name="app.tasks.reports.check_offline_agents")
def check_offline_agents():
    """Check for agents that haven't reported in over 15 minutes and alert."""
    loop = asyncio.get_event_loop()
    if loop.is_running():
        asyncio.ensure_future(_check_offline_async())
    else:
        loop.run_until_complete(_check_offline_async())


async def _check_offline_async():
    threshold = datetime.utcnow() - timedelta(minutes=15)
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Agent).where(Agent.LastSeen < threshold)
        )
        offline_agents = result.scalars().all()
        if offline_agents:
            print(f"[OfflineCheck] {len(offline_agents)} agents offline: {[a.Hostname for a in offline_agents[:5]]}")
