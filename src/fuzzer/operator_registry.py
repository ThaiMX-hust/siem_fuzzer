# src/fuzzer/operator_registry.py
import re
import random
from typing import Dict, List, Tuple

class Operator:
    def __init__(self, name: str, sample: str):
        self.name = name
        self.sample = sample

class OperatorGroup:
    def __init__(self, name: str, operators: List[Operator]):
        self.name = name
        self.operators = operators
        self.q_g = 0.1
        self.n_g = 0

class OperatorRegistry:
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
