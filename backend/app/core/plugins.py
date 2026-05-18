import os
import importlib
import inspect
from fastapi import APIRouter
import logging

logger = logging.getLogger("PluginManager")

class PluginManager:
    """[v2.1.0] Dynamic Feature Loader for Enterprise Modular Architecture."""
    
    def __init__(self, app=None):
        self.app = app
        self.plugins = []

    def load_api_plugins(self, api_package="app.api"):
        """Dynamically discovers and registers APIRouters from the api package."""
        if not self.app:
            return

        try:
            # Convert package to path
            package_path = api_package.replace(".", "/")
            full_path = os.path.abspath(os.path.join(os.getcwd(), package_path))
            
            if not os.path.exists(full_path):
                # Fallback for container/different CWD
                full_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "api"))

            for filename in os.listdir(full_path):
                if filename.endswith(".py") and not filename.startswith("__"):
                    module_name = f"{api_package}.{filename[:-3]}"
                    try:
                        module = importlib.import_module(module_name)
                        
                        # Look for 'router' instance of APIRouter
                        for name, obj in inspect.getmembers(module):
                            if isinstance(obj, APIRouter):
                                prefix = f"/api/{filename[:-3]}"
                                # Special case for auth/main
                                if filename[:-3] in ["auth", "main"]:
                                     prefix = "/api"
                                     
                                self.app.include_router(obj, prefix=prefix, tags=[filename[:-3].capitalize()])
                                self.plugins.append(module_name)
                                logger.info(f"Loaded API Plugin: {module_name} -> {prefix}")
                                break
                    except Exception as me:
                        logger.error(f"Failed to load plugin module {module_name}: {me}")
        except Exception as e:
            logger.error(f"Plugin Discovery Error: {e}")

    def get_loaded_plugins(self):
        return self.plugins

# Singleton instance
plugin_manager = PluginManager()
