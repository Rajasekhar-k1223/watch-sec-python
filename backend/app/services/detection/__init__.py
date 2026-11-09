"""
Monitorix Enterprise Detection Engine Package
============================================
Native Sigma YAML Compiler, Detection Rule Evaluator, Alert Persistence,
System Rule Registry, and Real-Time Streaming Detection Engine.
"""

from .sigma_compiler import (
    SigmaCompiler,
    SigmaRuleRegistry,
    CompiledSigmaRule,
    DetectionResult,
    SigmaCompilationError,
    SigmaEvaluationError,
    sigma_compiler,
    sigma_registry,
    evaluate_event,
    evaluate_all,
)

__all__ = [
    # Sigma Compiler
    "SigmaCompiler",
    "SigmaRuleRegistry",
    "CompiledSigmaRule",
    "DetectionResult",
    "SigmaCompilationError",
    "SigmaEvaluationError",
    "sigma_compiler",
    "sigma_registry",
    "evaluate_event",
    "evaluate_all",
]

# Database & Async-dependent modules imported conditionally
try:
    from .system_rules import (
        RESERVED_SYSTEM_RULE_IDS,
        SYSTEM_RULES_DEFINITIONS,
        is_system_rule,
        get_system_rules,
        get_system_rule_by_id,
        seed_system_rules,
        validate_rule_modification_security,
    )
    __all__.extend([
        "RESERVED_SYSTEM_RULE_IDS",
        "SYSTEM_RULES_DEFINITIONS",
        "is_system_rule",
        "get_system_rules",
        "get_system_rule_by_id",
        "seed_system_rules",
        "validate_rule_modification_security",
    ])
except ImportError:
    pass

try:
    from .alert_persistence import (
        AlertPersistenceService,
        alert_persistence_service,
        DEDUPLICATION_WINDOW_MINUTES,
    )
    __all__.extend([
        "AlertPersistenceService",
        "alert_persistence_service",
        "DEDUPLICATION_WINDOW_MINUTES",
    ])
except ImportError:
    pass

try:
    from .streaming_detector import (
        StreamingDetectionEngine,
        streaming_detection_engine,
        SUPPORTED_EVENT_TYPES,
    )
    __all__.extend([
        "StreamingDetectionEngine",
        "streaming_detection_engine",
        "SUPPORTED_EVENT_TYPES",
    ])
except ImportError:
    pass
