# src/fuzzer/reward_engine.py
from typing import Dict

class RewardEngine:
    def __init__(self, weights: Dict = None):
        default = {"w_bypass": 0.6, "w_similarity": 0.25, "w_novelty": 0.1, "w_invalid": 0.3}
        self.w = weights or default

    def compute(self, detected: bool, similarity: float, novelty: float, invalid: bool) -> float:
        bypass = 0.0 if detected else 1.0
        r_raw = self.w["w_bypass"] * bypass + self.w["w_similarity"] * (1 - similarity) + self.w["w_novelty"] * novelty
        if invalid:
            r_raw -= self.w["w_invalid"]
        # clamp
        if r_raw > 1.0:
            r_raw = 1.0
        if r_raw < -1.0:
            r_raw = -1.0
        return r_raw
