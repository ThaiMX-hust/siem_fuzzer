# src/fuzzer/grammar_loader.py
from typing import Any, Dict
from .config import load_grammar

REQUIRED_TOP = ["meta", "terminals", "obfuscation_groups", "rules", "mutation_engine", "sampling"]

def load_and_validate() -> Dict[str, Any]:
    g = load_grammar()
    missing = [k for k in REQUIRED_TOP if k not in g]
    if missing:
        raise ValueError(f"grammar.json missing keys: {missing}")
    # minimal structure checks
    if "payload_core" not in g["rules"]:
        raise ValueError("rules.payload_core missing")
    return g
