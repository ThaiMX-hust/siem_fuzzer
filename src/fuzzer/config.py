# src/fuzzer/config.py
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GRAMMAR_PATH = ROOT / "conf" / "grammar.json"

def load_grammar() -> dict:
    with open(GRAMMAR_PATH, "r", encoding="utf-8") as f:
        return json.load(f)
