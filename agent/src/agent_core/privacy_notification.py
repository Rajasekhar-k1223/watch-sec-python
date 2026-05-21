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
                # Use base64 encoding to safely pass the message to PowerShell
                import base64
                msg_b64 = base64.b64encode(msg.encode('utf-16le')).decode('utf-8')
                ps_script = f"""
                [reflection.assembly]::loadwithpartialname('System.Windows.Forms');
                $notify = New-Object System.Windows.Forms.NotifyIcon;
                $notify.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon((Get-Process -id $pid).Path);
                $notify.BalloonTipIcon = 'Info';
                $msg = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('{msg_b64}'));
                $notify.BalloonTipText = $msg;
                $notify.BalloonTipTitle = 'Security Compliance';
                $notify.Visible = $true;
                $notify.ShowBalloonTip(10000);
                """
                subprocess.run(["powershell", "-Command", ps_script], capture_output=True)
            
            elif system == "Linux":
                # Using notify-send (common in GNOME/KDE)
                subprocess.run(["notify-send", "Security Compliance", msg], capture_output=True, timeout=5)
                
            elif system == "Darwin":
                # macOS AppleScript notification using safe variable passing
                # We can't pass args directly to AppleScript string easily, so we escape quotes
                safe_msg = msg.replace('"', '\\"')
                script = f'display notification "{safe_msg}" with title "Security Compliance"'
                subprocess.run(["osascript", "-e", script], capture_output=True)
                
        except Exception as e:
            # Silently fail if notification system is missing (e.g. headless server)
            pass

if __name__ == "__main__":
    PrivacyNotification.show_consent_notice("Test Tenant")
