"""Exception class names double as Step Functions error names (Lambda errorType)."""


class PreflightFailed(Exception):
    """Target is out of scope, protected, missing or the role lacks permission."""


class BreakerOpen(Exception):
    """Too many isolations in the window: stop automation and ask a human."""


class VerificationFailed(Exception):
    """Post-action check did not observe the expected state."""
