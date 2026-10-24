# gate/semantic_check.py
"""Thin wrapper exposing a uniform ``semantic_check`` API.

The heavy embedding model lives in ``semantic_firewall.py``.  This wrapper
provides a stable function name that ``AdapterBase`` can import without pulling
in the large dependencies unless the check is actually needed.
"""

from .semantic_firewall import is_unsafe_prompt


def semantic_check(prompt: str) -> bool:
    """Return ``True`` if the prompt is **safe**.

    The underlying ``is_unsafe_prompt`` returns ``True`` for *unsafe* prompts;
    we invert the result so the rest of the code base can keep the
    ``if not semantic_check(...): raise PermissionError`` logic.
    """
    return not is_unsafe_prompt(prompt)
