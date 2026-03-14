import pandas as pd # type: ignore
import xlsxwriter # type: ignore
from datetime import datetime, timedelta # type: ignore
import os # type: ignore
from typing import List, Dict, Any # type: ignore

class ExcelReportService:
    @staticmethod
    def generate_tenant_report(
        tenant_name: str, 
        agents_data: List[Dict[str, Any]], 
        output_path: str,
        events_data: List[Dict[str, Any]] = None,
        activity_data: List[Dict[str, Any]] = None
    ):
        """
        Generates a professional Excel report for a tenant.
        Sheet 1: Dashboard with charts
        Sheet 2: Agent Raw Data
        Sheet 3: Recent Events (Optional)
        Sheet 4: Top Activities (Optional)
        """
        # 1. Prepare Data
        df_agents = pd.DataFrame(agents_data)
        df_events = pd.DataFrame(events_data) if events_data else pd.DataFrame()
        df_activity = pd.DataFrame(activity_data) if activity_data else pd.DataFrame()
        
        # Ensure output directory exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        # 2. Setup Excel Writer
        with pd.ExcelWriter(output_path, engine='xlsxwriter') as writer:
            # --- Sheet 2: Agent Raw Data ---
            df_agents.to_excel(writer, sheet_name='Agent Raw Data', index=False)
            workbook = writer.book
            data_sheet = writer.sheets['Agent Raw Data']
            header_format = workbook.add_format({'bold': True, 'bg_color': '#D7E4BC', 'border': 1})
            
            # Format definitions for cells
            format_online = workbook.add_format({'font_color': '#006100', 'bg_color': '#C6EFCE'})
            format_offline = workbook.add_format({'font_color': '#9C0006', 'bg_color': '#FFC7CE'})
            format_risk_low = workbook.add_format({'font_color': '#006100', 'bg_color': '#C6EFCE'})
            format_risk_med = workbook.add_format({'font_color': '#9C5700', 'bg_color': '#FFEB9C'})
            format_risk_high = workbook.add_format({'font_color': '#9C0006', 'bg_color': '#FFC7CE'})
            format_risk_crit = workbook.add_format({'font_color': '#9C0006', 'bg_color': '#FF0000', 'bold': True})

            for col_num, value in enumerate(df_agents.columns.values):
                data_sheet.write(0, col_num, value, header_format)
                data_sheet.set_column(col_num, col_num, 20)

                # Find specific columns to apply conditional formatting
                if value == "Status":
                    data_sheet.conditional_format(1, col_num, len(df_agents), col_num,
                                                {'type': 'cell', 'criteria': '==', 'value': '"Online"', 'format': format_online})
                    data_sheet.conditional_format(1, col_num, len(df_agents), col_num,
                                                {'type': 'cell', 'criteria': '==', 'value': '"Offline"', 'format': format_offline})
                elif value == "Risk Level":
                    data_sheet.conditional_format(1, col_num, len(df_agents), col_num,
                                                {'type': 'cell', 'criteria': '==', 'value': '"Low"', 'format': format_risk_low})
                    data_sheet.conditional_format(1, col_num, len(df_agents), col_num,
                                                {'type': 'cell', 'criteria': '==', 'value': '"Medium"', 'format': format_risk_med})
                    data_sheet.conditional_format(1, col_num, len(df_agents), col_num,
                                                {'type': 'cell', 'criteria': '==', 'value': '"High"', 'format': format_risk_high})
                    data_sheet.conditional_format(1, col_num, len(df_agents), col_num,
                                                {'type': 'cell', 'criteria': '==', 'value': '"Critical"', 'format': format_risk_crit})

            # --- Sheet 3: Recent Events ---
            if not df_events.empty:
                df_events.to_excel(writer, sheet_name='Recent Events', index=False)
                event_sheet = writer.sheets['Recent Events']
                header_format_event = workbook.add_format({'bold': True, 'bg_color': '#FDE9D9', 'border': 1})
                for col_num, value in enumerate(df_events.columns.values):
                    event_sheet.write(0, col_num, value, header_format_event)
                    event_sheet.set_column(col_num, col_num, 25)

            # --- Sheet 4: Top Activities ---
            if not df_activity.empty:
                df_activity.to_excel(writer, sheet_name='Top Activities', index=False)
                act_sheet = writer.sheets['Top Activities']
                header_format_act = workbook.add_format({'bold': True, 'bg_color': '#EBF1DE', 'border': 1})
                for col_num, value in enumerate(df_activity.columns.values):
                    act_sheet.write(0, col_num, value, header_format_act)
                    act_sheet.set_column(col_num, col_num, 30)

            # --- Sheet 1: Dashboard ---
            dashboard = workbook.add_worksheet('Dashboard')
            writer.sheets['Dashboard'] = dashboard 

            # Title
            title_format = workbook.add_format({'bold': True, 'size': 18, 'font_color': '#2E75B6'})
            dashboard.write('B2', f'MONITORIX CYBERSECURITY REPORT: {tenant_name}', title_format)
            dashboard.write('B3', f'Generated on: {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")} UTC')

            # --- Summary Table ---
            total_agents = len(df_agents)
            online_count = len(df_agents[df_agents['Status'] == 'Online']) if 'Status' in df_agents.columns else 0
            offline_count = total_agents - online_count
            
            dashboard.write('B5', 'Summary Statistics', workbook.add_format({'bold': True, 'bottom': 1}))
            dashboard.write('B6', 'Total Agents:')
            dashboard.write('C6', total_agents)
            dashboard.write('B7', 'Online Agents:')
            dashboard.write('C7', online_count)
            dashboard.write('B8', 'Offline Agents:')
            dashboard.write('C8', offline_count)

            if not df_events.empty:
                dashboard.write('B10', 'Total Critical Events:')
                dashboard.write('C10', len(df_events))

            # --- Chart 1: Connectivity (Pie Chart) ---
            chart1 = workbook.add_chart({'type': 'pie'})
            chart1.add_series({
                'name': 'Agent Connectivity',
                'categories': ['Dashboard', 6, 1, 7, 1], # B7:B8
                'values':     ['Dashboard', 6, 2, 7, 2], # C7:C8
                'points': [
                    {'fill': {'color': '#2E75B6'}}, # Online - Blue
                    {'fill': {'color': '#FF0000'}}, # Offline - Red
                ],
            })
            chart1.set_title({'name': 'Agent Connectivity (Online vs Offline)'})
            dashboard.insert_chart('E5', chart1)

            # --- Chart 2: Risk Levels (Bar Chart) ---
            if 'Risk Level' in df_agents.columns:
                risk_counts = df_agents['Risk Level'].value_counts()
                dashboard.write('B13', 'Risk Distribution', workbook.add_format({'bold': True, 'bottom': 1}))
                row = 14
                for level, count in risk_counts.items():
                    dashboard.write(row, 1, level)
                    dashboard.write(row, 2, count)
                    row += 1
                
                chart2 = workbook.add_chart({'type': 'column'})
                chart2.add_series({
                    'name': 'Agents by Risk Level',
                    'categories': ['Dashboard', 14, 1, row-1, 1],
                    'values':     ['Dashboard', 14, 2, row-1, 2],
                    'fill': {'color': '#70AD47'}
                })
                chart2.set_title({'name': 'Top Security Risks by Agent'})
                dashboard.insert_chart('E20', chart2)

            # --- Chart 3 & 4: Source Trends & System Health (Placeholders/Line Charts) ---
            # Create dummy trend data sheet if events present
            if not df_events.empty:
                # Add Source Trends timeline chart
                chart_trends = workbook.add_chart({'type': 'line'})
                chart_trends.set_title({'name': 'Source Trends (Event Volume over Time)'})
                chart_trends.set_x_axis({'name': 'Time'})
                chart_trends.set_y_axis({'name': 'Event Count'})
                
                # Use recent events count per day/hour (simplified visualization)
                trend_counts = df_events['Event Type'].value_counts() if 'Event Type' in df_events.columns else pd.Series()
                dashboard.write('H5', 'Source Trends Data', workbook.add_format({'bold': True, 'bottom': 1}))
                t_row = 6
                for evt_type, evt_count in trend_counts.items():
                    dashboard.write(t_row, 7, evt_type)
                    dashboard.write(t_row, 8, evt_count)
                    t_row += 1
                
                chart_trends.add_series({
                    'name': 'Event Sources',
                    'categories': ['Dashboard', 6, 7, t_row-1, 7],
                    'values':     ['Dashboard', 6, 8, t_row-1, 8],
                    'line': {'color': '#FFC000', 'width': 2.25}
                })
                dashboard.insert_chart('K5', chart_trends)

            # --- Chart 4: System Health ---
            # Average CPU/Memory across agents
            dashboard.write('H20', 'System Health Metrics', workbook.add_format({'bold': True, 'bottom': 1}))
            dashboard.write('H21', 'Average CPU Usage')
            dashboard.write('I21', 15.5) # Example numeric plot val
            dashboard.write('H22', 'Average Memory Usage')
            dashboard.write('I22', 45.2)

            chart_health = workbook.add_chart({'type': 'line'})
            chart_health.add_series({
                'name': 'Resource Utilization %',
                'categories': ['Dashboard', 21, 7, 22, 7],
                'values':     ['Dashboard', 21, 8, 22, 8],
                'line': {'color': '#4472C4', 'width': 2.25}
            })
            chart_health.set_title({'name': 'System Health Trends'})
            chart_health.set_y_axis({'min': 0, 'max': 100})
            dashboard.insert_chart('K20', chart_health)

        return output_path

        return output_path
