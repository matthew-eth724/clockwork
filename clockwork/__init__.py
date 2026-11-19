"""Clockwork Engineering — an evidence-gated, graph-native runtime for
multi-agent vulnerability research.

The investigation is the graph: the graph decides what agents see, what they may
do, what counts as proven, and what the system learns.
"""
__version__ = "0.1.0"

from .runtime import AuthorityError, GateError, Runtime  # noqa: F401
