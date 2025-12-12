# src/fuzzer/generator.py
import random
from typing import List
from .config import load_grammar
from .grammar_loader import load_and_validate
from .seed_store import SeedStore
from .operator_registry import OperatorRegistry
from .mab.bandit import EpsilonGreedyBandit
from .validator import Validator, canonicalize_payload
from .siem_client import SiemSimulator
from .reward_engine import RewardEngine

class PayloadGenerator:
    def __init__(self, grammar: dict):
        self.grammar = grammar
        self.validator = Validator(grammar)
        # simple initial seeds
        seeds = [
            "net.exe start Spooler",
            "net1.exe start Spooler",
            "sc.exe start Spooler",
            "powershell.exe Start-Service Spooler"
        ]
        self.seed_store = SeedStore(seeds, rng_seed=1)
        self.op_registry = OperatorRegistry(grammar, rng_seed=2)
        groups = self.op_registry.list_groups()
        self.op_bandit = EpsilonGreedyBandit(groups, q_init=0.1, seed=3)
        self.siem = SiemSimulator(grammar)
        self.rewarder = RewardEngine()
        self.rng = random.Random(42)
        self.max_mut = int(grammar["mutation_engine"]["max_mutations"])
        self.eps_seed = float(grammar["sampling"]["epsilon_seed"])
        self.eps_group = float(grammar["sampling"]["epsilon_group"])
        self.corpus_successful: List[str] = []

    def pick_weighted(self, items, key="tok"):
        total = sum(x.get("weight",1.0) for x in items)
        r = self.rng.random() * total
        upto = 0.0
        for it in items:
            w = it.get("weight",1.0)
            upto += w
            if upto >= r:
                return it.get(key)
        return items[-1].get(key)

    def build_core_from_seed(self, seed: str):
        # override if seed contains wrapper/noise
        if "cmd.exe" in seed or "|" in seed or "&::" in seed or '"' in seed:
            return seed, "override"
        # try match exe start arg
        import re
        m = re.search(r"(\S+\.exe)\s+start\s+(\S+)", seed, flags=re.IGNORECASE)
        if m:
            exe = m.group(1)
            arg = m.group(2)
            core = f"{exe} start {arg}"
            return core, "canonical"
        # fallback: sample terminals
        exe = self.pick_weighted(self.grammar["terminals"]["executables"], key="tok")
        arg = self.rng.choice(self.grammar["terminals"]["arguments"][0]["examples"])
        core = f"{exe} start {arg}"
        return core, "fallback"

    def choose_wrapper(self):
        return self.pick_weighted(self.grammar["terminals"]["wrappers"], key="fmt")

    def apply_mutations(self, core: str):
        applied = []
        k = self.rng.randint(1, self.max_mut)
        cur = core
        for _ in range(k):
            g = self.op_bandit.select_arm(self.eps_group)
            op = self.op_registry.choose_operator_from_group(g)
            new = self.op_registry.apply_operator(op, cur)
            if not self.validator.quick_check(new):
                continue
            cur = new
            applied.append(g)
        return cur, applied

    def generate_one(self):
        seed = self.seed_store.select_seed_epsilon(self.eps_seed)
        core, mode = self.build_core_from_seed(seed.string)
        wrapper = self.choose_wrapper()
        mutated_core, applied = self.apply_mutations(core)
        payload = wrapper.format(mutated_core)
        valid = self.validator.full_check(payload, self.grammar["meta"]["max_payload_len"])
        sim = self.siem.analyze(payload)
        novelty = 1.0  # placeholder; compute more precisely if you store corpus
        reward = self.rewarder.compute(sim["detected"], sim["similarity"], novelty, not valid)
        # update seed and operator bandit
        self.seed_store.update_seed(seed.id, reward)
        for g in set(applied):
            self.op_bandit.update(g, reward)
        if (not sim["detected"]) and valid:
            self.corpus_successful.append(canonicalize_payload(mutated_core))
            self.seed_store.boost_seed(seed.id, boost_scale=0.4)
        return {
            "payload": payload,
            "valid": valid,
            "detected": sim["detected"],
            "similarity": sim["similarity"],
            "reward": reward,
            "seed_id": seed.id,
            "applied_groups": applied
        }

    def run_batch(self, n: int = 20):
        logs = []
        for i in range(n):
            r = self.generate_one()
            logs.append(r)
            print(f"[{i+1}/{n}] payload={r['payload']!r} valid={r['valid']} detected={r['detected']} reward={r['reward']:.3f}")
        print("\n-- operator Q --")
        for a, q in self.op_bandit.q.items():
            print(f"{a}: q={q:.3f} n={self.op_bandit.n[a]}")
        print("-- seed Q --")
        for s in self.seed_store.list_seeds():
            print(f"{s.id}: q_s={s.q_s:.3f} n={s.n_s} str={s.string!r}")
        return logs

if __name__ == "__main__":
    grammar = load_and_validate()
    gen = PayloadGenerator(grammar)
    gen.run_batch(30)
