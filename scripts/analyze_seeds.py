"""
Analyze seed collection with JSON format support
"""
import json
import sys
from pathlib import Path
from collections import Counter
from typing import Dict, List

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from fuzzer.grammar_loader import load_and_validate
from fuzzer.validator import Validator

class SeedAnalyzer:
    def __init__(self, seeds_dir: Path):
        self.seeds_dir = seeds_dir
        self.stats = {
            "total_seeds": 0,
            "by_rule": {},
            "executables": Counter(),
            "techniques": {
                "caret_insertion": 0,
                "case_mixing": 0,
                "quote_wrapping": 0,
                "env_vars": 0,
                "long_form_flags": 0,
                "omit_extension": 0,
                "ip_encoding": 0,
                "evasion_insertion": 0,
                "evasion_substitution": 0,
                "evasion_omission": 0,
                "evasion_reordering": 0,
                "evasion_recoding": 0,
            },
            "mab_stats": {
                "avg_q_value": 0.0,
                "avg_selection_count": 0.0,
                "high_performers": [],
                "low_performers": [],
            }
        }
    
    def load_seeds_from_file(self, file_path: Path) -> List[Dict]:
        """Load seeds from JSON or TXT file"""
        seeds = []
        
        if file_path.suffix == '.json':
            # JSON format (structured)
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    
                    # Handle both array and object format
                    if isinstance(data, list):
                        seeds = data
                    elif isinstance(data, dict) and "seeds" in data:
                        seeds = data["seeds"]
                    else:
                        print(f"[!] Unknown JSON format in {file_path}")
            except json.JSONDecodeError as e:
                print(f"[!] Invalid JSON in {file_path}: {e}")
        
        elif file_path.suffix == '.txt':
            # Plain text format (backward compatibility)
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        seeds.append({
                            "string": line,
                            "q_s": 0.1,
                            "n_s": 0,
                            "invalid_count": 0
                        })
        
        return seeds
    
    def analyze_seed(self, seed: Dict, rule_name: str):
        """Analyze individual seed"""
        self.stats["total_seeds"] += 1
        
        # Initialize rule stats if not exists
        if rule_name not in self.stats["by_rule"]:
            self.stats["by_rule"][rule_name] = {
                "count": 0,
                "avg_q": 0.0,
                "total_selections": 0,
                "samples": []
            }
        
        rule_stats = self.stats["by_rule"][rule_name]
        rule_stats["count"] += 1
        
        # Extract seed string
        seed_str = seed.get("string", "")
        
        # Store sample
        if len(rule_stats["samples"]) < 3:
            rule_stats["samples"].append(seed_str)
        
        # MAB statistics
        q_s = seed.get("q_s", 0.1)
        n_s = seed.get("n_s", 0)
        rule_stats["avg_q"] += q_s
        rule_stats["total_selections"] += n_s
        
        # Detect executable
        for exe in ["net.exe", "sc.exe", "powershell", "cmd", "wmic", "schtasks", "curl"]:
            if exe in seed_str.lower():
                self.stats["executables"][exe] += 1
        
        # Detect evasion techniques
        if "^" in seed_str:
            self.stats["techniques"]["caret_insertion"] += 1
        
        if any(c.isupper() for c in seed_str) and any(c.islower() for c in seed_str):
            self.stats["techniques"]["case_mixing"] += 1
        
        if '"' in seed_str or "'" in seed_str:
            self.stats["techniques"]["quote_wrapping"] += 1
        
        if "%" in seed_str:
            self.stats["techniques"]["env_vars"] += 1
        
        if "--" in seed_str:
            self.stats["techniques"]["long_form_flags"] += 1
        
        # Omission: no .exe extension
        if not ".exe" in seed_str.lower():
            if any(exe.replace(".exe", "") in seed_str.lower() for exe in ["net", "sc", "wmic"]):
                self.stats["techniques"]["omit_extension"] += 1
        
        # IP encoding
        if any(char.isdigit() for char in seed_str) and "." not in seed_str:
            # Possible decimal IP encoding
            self.stats["techniques"]["ip_encoding"] += 1
        
        # Detect 5 evasion types (from paper)
        if '/"' in seed_str or '/""' in seed_str:
            self.stats["techniques"]["evasion_insertion"] += 1
        
        if "-ExecutionPolicy" in seed_str or "--remote-name" in seed_str:
            self.stats["techniques"]["evasion_substitution"] += 1
        
        if not ".exe" in seed_str.lower():
            self.stats["techniques"]["evasion_omission"] += 1
    
    def finalize_stats(self):
        """Calculate final statistics"""
        total = self.stats["total_seeds"]
        
        if total == 0:
            return
        
        # Calculate MAB averages
        all_q_values = []
        all_n_values = []
        
        for rule_name, rule_stats in self.stats["by_rule"].items():
            if rule_stats["count"] > 0:
                rule_stats["avg_q"] /= rule_stats["count"]
                all_q_values.append(rule_stats["avg_q"])
                all_n_values.append(rule_stats["total_selections"])
        
        if all_q_values:
            self.stats["mab_stats"]["avg_q_value"] = sum(all_q_values) / len(all_q_values)
            self.stats["mab_stats"]["avg_selection_count"] = sum(all_n_values) / len(all_n_values)
    
    def print_report(self):
        """Print comprehensive analysis report"""
        print("=" * 70)
        print("SEED COLLECTION ANALYSIS")
        print("=" * 70)
        
        total = self.stats["total_seeds"]
        print(f"\n[*] Total Seeds: {total}")
        
        if total == 0:
            print("[!] No seeds found!")
            return
        
        # Seeds by Rule
        print("\n[*] Seeds by Rule:")
        for rule_name, rule_stats in sorted(self.stats["by_rule"].items()):
            print(f"\n  📁 {rule_name}:")
            print(f"     Count: {rule_stats['count']} seeds")
            print(f"     Avg Q-value: {rule_stats['avg_q']:.3f}")
            print(f"     Total Selections: {rule_stats['total_selections']}")
            
            if rule_stats['samples']:
                print(f"     Samples:")
                for i, sample in enumerate(rule_stats['samples'][:3], 1):
                    print(f"       {i}. {sample[:70]}...")
        
        # Executable Distribution
        print("\n[*] Executable Distribution:")
        if self.stats["executables"]:
            for exe, count in self.stats["executables"].most_common():
                percentage = count / total * 100
                print(f"    {exe}: {count} ({percentage:.1f}%)")
        else:
            print("    [!] No executables detected")
        
        # Evasion Technique Coverage
        print("\n[*] Evasion Technique Coverage:")
        for tech, count in sorted(self.stats["techniques"].items()):
            coverage = count / total * 100 if total > 0 else 0
            
            # Status indicators
            if coverage > 30:
                status = "✓"
                color = "GOOD"
            elif coverage > 15:
                status = "⚠"
                color = "MEDIUM"
            else:
                status = "✗"
                color = "LOW"
            
            print(f"    {status} {tech:25s}: {count:3d} ({coverage:5.1f}%) [{color}]")
        
        # MAB Statistics
        print("\n[*] Multi-Armed Bandit Statistics:")
        print(f"    Average Q-value: {self.stats['mab_stats']['avg_q_value']:.3f}")
        print(f"    Average Selection Count: {self.stats['mab_stats']['avg_selection_count']:.1f}")
        
        # Recommendations
        print("\n[*] Recommendations:")
        recommendations = []
        
        for tech, count in self.stats["techniques"].items():
            coverage = count / total * 100
            
            if coverage < 15:
                recommendations.append(f"⚠ Increase {tech} coverage (current: {coverage:.1f}%)")
        
        if self.stats["mab_stats"]["avg_q_value"] < 0.2:
            recommendations.append("⚠ Low Q-values indicate poor seed quality")
        
        if not self.stats["executables"]:
            recommendations.append("⚠ No executables detected - check seed format")
        
        if recommendations:
            for rec in recommendations:
                print(f"    {rec}")
        else:
            print("    ✓ Seed collection looks healthy!")
        
        # Diversity Score
        diversity_score = self._calculate_diversity()
        print(f"\n[*] Diversity Score: {diversity_score:.1f}/100")
        
        if diversity_score < 40:
            print("    ⚠ LOW - Add more varied seeds")
        elif diversity_score < 70:
            print("    ⚠ MEDIUM - Good start, but can improve")
        else:
            print("    ✓ HIGH - Excellent seed diversity!")
    
    def _calculate_diversity(self) -> float:
        """Calculate seed diversity score (0-100)"""
        if self.stats["total_seeds"] == 0:
            return 0.0
        
        score = 0.0
        total = self.stats["total_seeds"]
        
        # Technique coverage (50 points)
        covered_techniques = sum(1 for count in self.stats["techniques"].values() if count > 0)
        max_techniques = len(self.stats["techniques"])
        score += (covered_techniques / max_techniques) * 50
        
        # Executable variety (30 points)
        num_executables = len(self.stats["executables"])
        score += min(num_executables / 7, 1.0) * 30  # 7 common executables
        
        # Seed quantity (20 points)
        score += min(total / 50, 1.0) * 20  # 50 seeds = full score
        
        return score

def validate_seeds_against_grammar(seeds_dir: Path):
    """Validate seeds against grammar rules"""
    print("\n" + "=" * 70)
    print("SEED VALIDATION")
    print("=" * 70)
    
    invalid_seeds = []
    
    for seed_file in seeds_dir.glob("*.json"):
        rule_name = seed_file.stem
        
        try:
            grammar = load_and_validate(rule_name=rule_name)
            validator = Validator(grammar)
            
            analyzer = SeedAnalyzer(seeds_dir)
            seeds = analyzer.load_seeds_from_file(seed_file)
            
            print(f"\n[*] Validating {rule_name} ({len(seeds)} seeds)...")
            
            valid_count = 0
            for seed in seeds:
                seed_str = seed.get("string", "")
                if validator.quick_check(seed_str):
                    valid_count += 1
                else:
                    invalid_seeds.append((rule_name, seed_str))
            
            print(f"    Valid: {valid_count}/{len(seeds)} ({valid_count/len(seeds)*100:.1f}%)")
            
        except Exception as e:
            print(f"[!] Error validating {rule_name}: {e}")
    
    if invalid_seeds:
        print("\n[!] Invalid Seeds Found:")
        for rule_name, seed_str in invalid_seeds[:10]:
            print(f"    {rule_name}: {seed_str[:60]}...")
        
        if len(invalid_seeds) > 10:
            print(f"    ... and {len(invalid_seeds) - 10} more")

def main():
    seeds_dir = Path(__file__).parent.parent / "conf" / "seeds"
    
    if not seeds_dir.exists():
        print(f"[!] Seeds directory not found: {seeds_dir}")
        print("[*] Please create seeds directory and add seed files")
        return
    
    # Check for seed files
    json_files = list(seeds_dir.glob("*.json"))
    txt_files = list(seeds_dir.glob("*.txt"))
    
    if not json_files and not txt_files:
        print(f"[!] No seed files found in {seeds_dir}")
        print("[*] Expected files: *.json or *.txt")
        return
    
    # Analyze all seeds
    analyzer = SeedAnalyzer(seeds_dir)
    
    for seed_file in json_files + txt_files:
        seeds = analyzer.load_seeds_from_file(seed_file)
        rule_name = seed_file.stem
        
        for seed in seeds:
            analyzer.analyze_seed(seed, rule_name)
    
    analyzer.finalize_stats()
    analyzer.print_report()
    
    # Validate against grammar
    validate_seeds_against_grammar(seeds_dir)
    
    print("\n" + "=" * 70)

if __name__ == "__main__":
    main()