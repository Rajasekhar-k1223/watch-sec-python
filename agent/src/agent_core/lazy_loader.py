import importlib
import sys
import types
import logging

logger = logging.getLogger("LazyLoader")

class LazyModule(types.ModuleType):
    """[v2.1.0] Proxy for a module that is only loaded upon first access."""
    
    def __init__(self, name, package=None):
        super().__init__(name)
        self._name = name
        self._package = package
        self._module = None

    def _load(self):
        if self._module is None:
            try:
                # logger.info(f"Dynamically loading heavy module: {self._name}")
                self._module = importlib.import_module(self._name, self._package)
                # Sync our __dict__ with the loaded module
                self.__dict__.update(self._module.__dict__)
            except Exception as e:
                # logger.error(f"Lazy load failed for {self._name}: {e}")
                raise e
        return self._module

    def __getattr__(self, item):
        module = self._load()
        return getattr(module, item)

    def __dir__(self):
        module = self._load()
        return dir(module)

def lazy_import(name, package=None):
    """Factory for LazyModule."""
    return LazyModule(name, package)
