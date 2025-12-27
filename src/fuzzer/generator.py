# src/fuzzer/generator.py
import random
from typing import List ,Tuple, Optional
import re
from .config import load_grammar
from .grammar_loader import load_and_validate
from .seed_store import SeedStore
from .operator_registry import OperatorRegistry
from .mab.bandit import EpsilonGreedyBandit
from .validator import Validator, canonicalize_payload
from .siem_client import OpenSearchClient
from .reward_engine import RewardEngine



class PayloadGenerator:
    def __init__(self, grammar: dict, custom_seeds: list = None):
        self.grammar = grammar
        self.validator = Validator(grammar)
        # simple initial seeds
        seeds = custom_seeds
        self.seed_store = SeedStore(seeds, rng_seed=1)
        self.op_registry = OperatorRegistry(grammar, rng_seed=2)
        groups = self.op_registry.list_groups()
        self.op_bandit = EpsilonGreedyBandit(groups, q_init=0.1, seed=3)

        OPENSEARCH_HOST = "192.168.1.100"
        OPENSEARCH_AUTH = ("admin", "admin")
        self.siem = OpenSearchClient(grammar, host=OPENSEARCH_HOST, auth=OPENSEARCH_AUTH)
        
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
    

    def _canonicalize_for_match(self, s: str) -> str:
        """
        Canonicalize nhẹ để phục vụ regex match:
        - remove caret
        - normalize spaces
        - keep case-insensitive
        """
        s = s.replace("^", "")
        s = re.sub(r"\s+", " ", s).strip()  
        return s
    

    def build_core_from_seed(self, seed: str) -> Tuple[str, str]:
        """
        Build core payload from seed with priority:
        1. Parse seed matching grammar structure → canonical
        2. If seed has strong wrapper/noise → override
        3. Otherwise → fallback canonical
        """
        seed_norm = self._canonicalize_for_match(seed)

        # Step 1: Try parse to canonical
        canonical = self._parse_seed_to_canonical(seed_norm)
        if canonical is not None:
            if self._has_strong_wrapper(seed_norm):
                return seed, "override"
            return canonical, "canonical"

        # Step 2: Wrapper but cannot parse
        if self._has_strong_wrapper(seed_norm):
            return seed, "override"

        # Step 3: Fallback
        return self._generate_canonical_from_grammar(), "fallback"
    
    def _parse_seed_to_canonical(self, seed: str) -> Optional[str]:
        """
        Parse seed according to grammar.rules.payload_core.structure.
        Returns canonical payload or None.
        """
        rules = self.grammar.get("rules", {})
        payload_core = rules.get("payload_core")
        if not payload_core:
            return None

        structures = payload_core.get("structures")
        if not structures or len(structures) == 0:
            return None

        for structure in structures:
            canonical = self._try_parse_with_structure(seed,structure)
            if canonical:
                return canonical
        return None

    def _try_parse_with_structure(self, seed: str, structure: list) -> Optional[str]:
        """Try to parse seed with a specific structure"""
        pattern_parts = []
        capture_steps = []

        for step in structure:
            t = step["type"]

            if t == "choose":
                from_key = step["from"]
                terminals = self.grammar["terminals"].get(from_key, [])
                alts = []

                for term in terminals:
                    tok = term.get("tok", "")
                    if tok.startswith("<") and tok.endswith(">"):
                        alts.append(r"\S+")
                    else:
                        alts.append(re.escape(tok))

                # ONE capturing group per choose
                pattern_parts.append(f"({'|'.join(alts)})")
                capture_steps.append(step)

            elif t == "literal":
                pattern_parts.append(re.escape(step["tok"]))

            elif t == "sep":
                pattern_parts.append(re.escape(step["tok"]))

            else:
                return None  # unknown grammar type

        pattern = "^" + "".join(pattern_parts) + "$"
        match = re.match(pattern, seed, flags=re.IGNORECASE)
        if not match:
            return None

        # Rebuild canonical payload
        canonical_parts = []
        group_idx = 1

        for step in structure:
            t = step["type"]
            if t == "choose":
                canonical_parts.append(match.group(group_idx))
                group_idx += 1
            elif t == "literal":
                canonical_parts.append(step["tok"])
            elif t == "sep":
                canonical_parts.append(step["tok"])

        canonical = "".join(canonical_parts)
        canonical = self._canonicalize_for_match(canonical)

        if self._matches_constraints(canonical):
            return canonical

        return None

    def _has_strong_wrapper(self, seed: str) -> bool:
        """
        Detect real wrappers / shell constructs.
        Executables themselves (e.g. powershell.exe) are NOT wrappers.
        """
        s = seed.lower()

        strong_wrappers = [
            "cmd.exe /c",
            "cmd /c",
            "echo ",
            "|",
            "&&",
            "&::",
        ]

        for w in strong_wrappers:
            if w in s:
                return True

        # fully wrapped in quotes
        if seed.startswith('"') and seed.endswith('"'):
            return True

        return False
    def _matches_constraints(self, payload: str) -> bool:
        """
        Validate payload against grammar constraints
        """
        rules = self.grammar.get("rules", {})
        payload_core = rules.get("payload_core", {})
        constraints = payload_core.get("constraints", {})

        canon = self._canonicalize_for_match(payload)

        # Handle must_contain_keyword (single string - for backward compatibility)
        keyword = constraints.get("must_contain_keyword")
        if keyword:
            if isinstance(keyword, str):
                if keyword not in canon:
                    return False
            elif isinstance(keyword, list):
                # If it's a list, treat as must_contain_all
                for kw in keyword:
                    if kw not in canon:
                        return False
    
        # Handle must_contain_all (array of keywords)
        must_contain_all = constraints.get("must_contain_all")
        if must_contain_all:
            for kw in must_contain_all:
                if kw not in canon:
                    return False

        # Handle regex_positive
        regex_pos = constraints.get("regex_positive")
        if regex_pos and not re.search(regex_pos, canon, flags=re.IGNORECASE):
            return False

        return True

    def _generate_canonical_from_grammar(self) -> str:
        """
        Generate canonical payload strictly following grammar structures.
        Always returns constraint-valid payload.
        """
        rules = self.grammar.get("rules", {})
        payload_core = rules.get("payload_core")
        if not payload_core:
            # Check if terminals exist
            if "executables" not in self.grammar.get("terminals", {}):
                raise ValueError("Grammar missing required 'terminals.executables'")
            
            exe = self.pick_weighted(self.grammar["terminals"]["executables"], key="tok")
            arg = self.rng.choice(self.grammar["terminals"]["arguments"][0]["examples"])
            return f"{exe} start {arg}"

        structures = payload_core.get("structures")  # ← Đổi từ "structure"
        if not structures or len(structures) == 0:
            raise ValueError("Grammar missing 'structures' in payload_core")
        
        # Pick first structure (hoặc random nếu muốn)
        structure = structures[0]

        MAX_RETRIES = 10
        for attempt in range(MAX_RETRIES):
            parts = []

            for step in structure:
                t = step["type"]

                if t == "choose":
                    from_key = step["from"]
                    terminals = self.grammar["terminals"].get(from_key, [])
                    
                    if not terminals:
                        raise ValueError(f"No terminals found for key '{from_key}'")

                    # Handle examples
                    if terminals[0].get("examples"):
                        tok = self.rng.choice(terminals[0]["examples"])
                    else:
                        tok = self.pick_weighted(terminals, key="tok")
                        
                        # Handle placeholder tokens like <other_exe_placeholder>
                        if tok.startswith("<") and tok.endswith(">"):
                            placeholder_name = tok[1:-1]  # Remove < >
                            
                            # Get real tokens from same terminal list
                            real_tokens = [t["tok"] for t in terminals if not t["tok"].startswith("<")]
                            
                            if real_tokens:
                                tok = self.rng.choice(real_tokens)
                            else:
                                # Fallback to generic value
                                tok = "placeholder_value"

                    parts.append(tok)

                elif t == "literal":
                    parts.append(step["tok"])

                elif t == "sep":
                    parts.append(step["tok"])

            candidate = "".join(parts)
            candidate = self._canonicalize_for_match(candidate)

            if self._matches_constraints(candidate):
                return candidate

        # Log để debug
        print(f"[WARNING] Failed to satisfy constraints after {MAX_RETRIES} attempts")
        print(f"Last candidate: {candidate}")
        print(f"Constraints: {payload_core.get('constraints')}")
        
        # Return anyway (với warning) thay vì crash
        return candidate


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
        payload = wrapper.format(payload=mutated_core)
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
