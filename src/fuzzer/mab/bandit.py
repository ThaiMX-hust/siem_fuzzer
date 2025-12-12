# src/fuzzer/mab_bandit.py
import random
import math
from typing import List, Dict

class EpsilonGreedyBandit:
    def __init__(self, arms: List[str], q_init: float = 0.1, seed: int = 0):
        self.arms = list(arms)
        self.q: Dict[str, float] = {a: q_init for a in self.arms}
        self.n: Dict[str, int] = {a: 0 for a in self.arms}
        self.rng = random.Random(seed)

    def select_arm(self, epsilon: float) -> str:
        if self.rng.random() < epsilon:
            return self.rng.choice(self.arms)
        maxq = max(self.arms, key=lambda a: self.q[a])
        maxval = self.q[maxq]
        candidates = [a for a in self.arms if abs(self.q[a] - maxval) < 1e-9]
        if len(candidates) > 1:
            return self.rng.choice(candidates)
        return maxq

    def update(self, arm: str, reward: float):
        self.n[arm] += 1
        self.q[arm] += (reward - self.q[arm]) / self.n[arm]
