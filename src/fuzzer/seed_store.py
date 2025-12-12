# src/fuzzer/seed_store.py
import random
import time
from typing import List, Dict, Optional

class Seed:
    def __init__(self, id: str, string: str, q_s: float = 0.1):
        self.id = id
        self.string = string
        self.q_s = float(q_s)
        self.n_s = 0
        self.invalid_count = 0
        self.last_used = 0.0

    def to_dict(self):
        return self.__dict__.copy()

class SeedStore:
    def __init__(self, seeds: List[str], rng_seed: int = 0):
        self.rng = random.Random(rng_seed)
        self.seeds: Dict[str, Seed] = {}
        for i, s in enumerate(seeds):
            sid = f"seed_{i+1:03d}"
            self.seeds[sid] = Seed(sid, s, q_s=0.1)

    def list_seeds(self) -> List[Seed]:
        return list(self.seeds.values())

    def select_seed_epsilon(self, epsilon: float):
        arr = self.list_seeds()
        if self.rng.random() < epsilon:
            return self.rng.choice(arr)
        # exploitation
        return max(arr, key=lambda s: s.q_s)

    def update_seed(self, seed_id: str, reward: float):
        s = self.seeds[seed_id]
        s.n_s += 1
        s.q_s += (reward - s.q_s) / s.n_s
        s.last_used = time.time()

    def boost_seed(self, seed_id: str, boost_scale: float = 0.5):
        s = self.seeds[seed_id]
        s.q_s = s.q_s + (1.0 - s.q_s) * boost_scale
