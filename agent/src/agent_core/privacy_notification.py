import platform
import subprocess
import os

class PrivacyNotification:
    """Utility to display monitoring consent notices to the end-user."""
    
    @staticmethod
    def show_consent_notice(tenant_name="Monitorix Enterprise"):
        """Displays a non-intrusive notification about active monitoring."""
        system = platform.system()
        msg = f"Device Security Audit Active. Monitored by {tenant_name} for compliance."
        
        try:
            if system == "Windows":
                # Using PowerShell to show a system toast notification
                ps_script = f"""
                [reflection.assembly]::loadwithpartialname('System.Windows.Forms');
                $notify = New-Object System.Windows.Forms.NotifyIcon;
                $notify.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon((Get-Process -id $pid).Path);
                $notify.BalloonTipIcon = 'Info';
                $notify.BalloonTipText = '{msg}';
                $notify.BalloonTipTitle = 'Security Compliance';
                $notify.Visible = $true;
                $notify.ShowBalloonTip(10000);
                """
                subprocess.run(["powershell", "-Command", ps_script], capture_output=True)
            
            elif system == "Linux":
                # Using notify-send (common in GNOME/KDE)
                subprocess.run(["notify-send", "Security Compliance", msg], capture_output=True)
                
            elif system == "Darwin":
                # macOS AppleScript notification
                script = f'display notification "{msg}" with title "Security Compliance"'
                subprocess.run(["osascript", "-e", script], capture_output=True)
                
        except Exception as e:
            # Silently fail if notification system is missing (e.g. headless server)
            pass

if __name__ == "__main__":
    PrivacyNotification.show_consent_notice("Test Tenant")
