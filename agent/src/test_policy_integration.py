import sys # type: ignore
import unittest # type: ignore
from unittest.mock import MagicMock, patch # type: ignore

# 1. Mock problematic imports and modules
sys.modules['winreg'] = MagicMock()
sys.modules['psutil'] = MagicMock()
sys.modules['socketio'] = MagicMock()
sys.modules['requests'] = MagicMock()
sys.modules['getpass'] = MagicMock()

# Mock core and modules
mock_core = MagicMock()
sys.modules['core'] = mock_core
sys.modules['core.bandwidth_manager'] = mock_core
sys.modules['modules'] = MagicMock()

# Add to path
sys.path.append('/opt/apps/monitorix/watch-sec-python/agent/src')

# Use a context manager to patch problematic parts of main.py during import
with patch('os.chdir'), patch('os.makedirs'), patch('platform.system', return_value='Linux'):
    try:
        # We need to mock the entire modules package so main.py doesn't try to import real modules
        # that might have dependencies we don't have here.
        import modules.fim # type: ignore
        import modules.network # type: ignore
        import modules.security # type: ignore
        import modules.mail_monitor # type: ignore
        import modules.browser_enforcer # type: ignore
        import modules.power_monitor # type: ignore
        import modules.webrtc_stream # type: ignore
        import modules.usb_monitor # type: ignore
        import modules.shadow_monitor # type: ignore
        import modules.network_monitor # type: ignore
        import modules.file_monitor # type: ignore
        import modules.hardware # type: ignore
        import modules.location_monitor # type: ignore
        import modules.network_utils # type: ignore
        import modules.speech_monitor # type: ignore
        import modules.audit_logger # type: ignore
        import modules.remote_desktop # type: ignore
        import modules.printer_monitor # type: ignore
        import modules.app_blocker # type: ignore
        import modules.remote_shell # type: ignore
        import modules.data_queue # type: ignore
        
        # Now import main
        import main # type: ignore
    except Exception as e:
        print(f"Import failed as expected (many modules might be missing), but let's see: {e}")

def test_apply_policy_integration():
    print("--- Testing apply_policy Integration ---")
    
    # Mock global instances in main
    main.bandwidth_manager = MagicMock()
    main.screen_cap = MagicMock()
    main.usb_ctrl = MagicMock()
    main.net_mon = MagicMock()
    
    test_config = {
        "BandwidthConfig": {
            "max_rate_kbps": 500,
            "business_hours": {"enabled": True}
        },
        "ScreenshotsEnabled": True,
        "UsbBlockingEnabled": True
    }
    
    # We need to mock save_config to avoid writing files
    with patch('main.save_config') as mock_save:
        main.apply_policy(test_config)
        
        # Check if bandwidth manager was updated
        main.bandwidth_manager.update_config.assert_called_with(test_config["BandwidthConfig"])
        print("✓ BandwidthManager.update_config called")
        
        # Check if other modules were updated
        main.screen_cap.set_enabled.assert_called_with(True)
        print("✓ screen_cap.set_enabled called")
        
        main.usb_ctrl.set_policy.assert_called_with("Block")
        print("✓ usb_ctrl.set_policy called")
        
        # Check if config was saved
        mock_save.assert_called()
        print("✓ save_config called")

    print("--- INTEGRATION TEST PASSED ---")

if __name__ == "__main__":
    test_apply_policy_integration()
