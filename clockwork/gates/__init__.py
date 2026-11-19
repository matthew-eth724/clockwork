"""Evidence-gate graph: machine-readable transition predicates and evaluator."""
from .engine import GateResult, evaluate_gate, next_gate  # noqa: F401
from .predicates import GATE_PREDICATES  # noqa: F401
