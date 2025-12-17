# src/fuzzer/operator_registry.py
import re
import random
from typing import Dict, List, Tuple

class Operator:
    """
    Operator represents a single obfuscation or mutation technique.

    Each operator contains:
    - name   : identifier of the operator
    - sample : example pattern used as a heuristic hint
               to decide how the operator should be applied
    """
    def __init__(self, name: str, sample: str):
        self.name = name
        self.sample = sample

class OperatorGroup:
    """
    OperatorGroup represents a group of related operators
    sharing the same obfuscation strategy.

    This class also stores bandit-related statistics
    for group-level learning.
    """
    def __init__(self, name: str, operators: List[Operator]):
        self.name = name
        self.operators = operators
        self.q_g = 0.1
        self.n_g = 0

class OperatorRegistry:
    """
    OperatorRegistry manages all operator groups and
    applies selected operators to core payloads.

    It acts as the mutation engine of the fuzzer.
    """
    def __init__(self, grammar: dict, rng_seed: int = 1):
        self.rng = random.Random(rng_seed)
        self.groups: Dict[str, OperatorGroup] = {}
        for gname, gdef in grammar.get("obfuscation_groups", {}).items():
            ops = [Operator(op["name"], op["sample"]) for op in gdef.get("operators", [])]
            self.groups[gname] = OperatorGroup(gname, ops)

    def list_groups(self) -> List[str]:
        return list(self.groups.keys())

    def choose_operator_from_group(self, group_name: str) -> Operator:
        g = self.groups[group_name]
        return self.rng.choice(g.operators)

    def apply_operator(self, op: Operator, core: str) -> str:
        """
        Apply the given operator to the core payload.

        The actual mutation logic is determined by
        heuristic checks on the operator's sample string.
        """
        s = core
        sample = op.sample
        # caret insertion heuristic
        if "^" in sample:
            s = re.sub(r"(\w+)(\.exe)", lambda m: m.group(1)[:1] + "^" + m.group(1)[1:] + m.group(2), s, count=1)
            return s
        # quote wrapper
        if sample.startswith('"') and sample.endswith('"'):
            s = re.sub(r'(\S+\.exe)', lambda m: f"\"{m.group(1)}\"", s, count=1)
            return s
        # uppercase
        if sample.isupper():
            s = re.sub(r"(\S+\.exe)", lambda m: m.group(1).upper(), s, count=1)
            return s
        return s
