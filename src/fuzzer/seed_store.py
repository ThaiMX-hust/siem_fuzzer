import random
from typing import List
from dataclasses import dataclass

@dataclass
class Seed:
    id: str
    string: str
    q_s: float = 0.1
    n_s: int = 0
    invalid_count: int = 0
    cluster_id: int = None
    last_used: int = 0


class SeedStore:
    def __init__(self, seeds, rng_seed=1):
        """
        Initialize seed store
        
        Args:
            seeds: Either:
                   - List of strings (plain seeds)
                   - List of dicts (seed objects with metadata)
            rng_seed: Random seed for reproducibility
        """
        self.rng = random.Random(rng_seed)
        self.seeds = []
        
        if not seeds:
            return
        
        # Check format of seeds
        if isinstance(seeds[0], dict):
            # Seeds with full metadata from JSON
            for seed_dict in seeds:
                self.seeds.append(Seed(
                    id=seed_dict.get("id", f"seed_{len(self.seeds)+1}"),
                    string=seed_dict["string"],
                    q_s=float(seed_dict.get("q_s", 0.1)),
                    n_s=int(seed_dict.get("n_s", 0)),
                    invalid_count=int(seed_dict.get("invalid_count", 0)),
                    cluster_id=seed_dict.get("cluster_id"),
                    last_used=seed_dict.get("last_used", 0)
                ))
        else:
            # Plain string seeds
            for i, s_str in enumerate(seeds):
                self.seeds.append(Seed(
                    id=f"seed_{i+1}",
                    string=s_str,
                    q_s=0.1,
                    n_s=0,
                    invalid_count=0,
                    cluster_id=None,
                    last_used=0
                ))

    def select_seed_epsilon(self, eps: float):
        """Epsilon-greedy seed selection"""
        if not self.seeds:
            raise ValueError("No seeds available")
        
        if self.rng.random() < eps:
            return self.rng.choice(self.seeds)  # Explore
        
        # Exploit: choose seed with highest Q-value
        best = max(self.seeds, key=lambda s: s.q_s)
        return best

    def update_seed(self, seed_id: str, reward: float):
        """Update Q-value using incremental average"""
        for s in self.seeds:
            if s.id == seed_id:
                s.n_s += 1
                s.q_s += (reward - s.q_s) / s.n_s
                break

    def boost_seed(self, seed_id: str, boost_scale: float = 0.4):
        """Boost Q-value for successful seed"""
        for s in self.seeds:
            if s.id == seed_id:
                s.q_s += (1.0 - s.q_s) * boost_scale
                break

    def list_seeds(self) -> List[Seed]:
        """Return all seeds"""
        return self.seeds