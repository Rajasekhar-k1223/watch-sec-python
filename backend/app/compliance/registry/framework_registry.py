"""
[v4.4.0] Framework Registry Facade
Exposes the authoritative 32-regulation statutory registry, supplemental security standards,
canonical ID resolver, and all 32 `run_<framework>_checks()` runners.
"""
from ..frameworks import (
    CORE_32_FRAMEWORK_CLASSES,
    SUPPLEMENTAL_FRAMEWORK_CLASSES,
    ALL_FRAMEWORK_CLASSES,
    CANONICAL_CORE_32_IDS,
    FRAMEWORK_REGISTRY,
    CANONICAL_FRAMEWORK_REGISTRY,
    FRAMEWORK_ALIASES,
    FRAMEWORK_RUNNER_MAP,
    resolve_canonical_framework_id,
    get_framework,
    list_registered_frameworks,
)

__all__ = [
    "CORE_32_FRAMEWORK_CLASSES",
    "SUPPLEMENTAL_FRAMEWORK_CLASSES",
    "ALL_FRAMEWORK_CLASSES",
    "CANONICAL_CORE_32_IDS",
    "FRAMEWORK_REGISTRY",
    "CANONICAL_FRAMEWORK_REGISTRY",
    "FRAMEWORK_ALIASES",
    "FRAMEWORK_RUNNER_MAP",
    "resolve_canonical_framework_id",
    "get_framework",
    "list_registered_frameworks",
]
