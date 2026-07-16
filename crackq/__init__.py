"""crackq — part of the Cognis Neural Suite."""
try:  # re-export the tool's public API + identity from core
    from crackq.core import *  # noqa: F401,F403
except Exception:  # pragma: no cover
    pass
try:  # re-export the password-analytics API
    from crackq.analyze import (  # noqa: F401
        analyze_password,
        analyze_batch,
        crack_report,
        classify_strength,
        estimate_entropy_bits,
        detect_patterns,
    )
except Exception:  # pragma: no cover
    pass
try:
    from crackq.core import TOOL_NAME, TOOL_VERSION
except Exception:  # pragma: no cover
    TOOL_NAME = "crackq"
    TOOL_VERSION = "0.1.0"
__version__ = TOOL_VERSION
