# src/fuzzer/siem_client.py
import re
from typing import Dict
from .validator import canonicalize_payload, normalize_spaces

class SiemSimulator:
    def __init__(self, grammar: Dict):
        self.regex = re.compile(grammar["constraints"]["regex_match"])

    def analyze(self, payload: str) -> Dict:
        can = canonicalize_payload(payload)
        detected = bool(self.regex.search(can))
        # compute simple similarity: normalized equal-ness
        sim = 1.0 if can == normalize_spaces(payload) else 0.5
        return {"detected": detected, "similarity": sim, "canonical": can}
