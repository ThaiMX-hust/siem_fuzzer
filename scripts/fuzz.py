#!/usr/bin/env python3
"""
Universal SIEM Rule Fuzzer
"""
import sys
import json
import argparse
from pathlib import Path
from datetime import datetime

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.fuzzer.generator import PayloadGenerator
from src.fuzzer.seed_store import SeedStore


def load_grammar(grammar_path: Path) -> dict:
    """Load grammar JSON file"""
    with open(grammar_path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_seeds(seed_path: Path) -> list:
    """
    Load seeds from text file or JSON file
    
    Supports two formats:
    1. Plain text (one seed per line)
    2. JSON array with seed objects (extracts "string" field)
    """
    if not seed_path.exists():
        print(f"[WARNING] Seed file not found: {seed_path}")
        return []
    
    # Try JSON format first
    try:
        with open(seed_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            
        # If it's a JSON array of seed objects
        if isinstance(data, list):
            seeds = []
            for item in data:
                if isinstance(item, dict) and "string" in item:
                    seeds.append(item["string"])
                elif isinstance(item, str):
                    seeds.append(item)
            return seeds
    except json.JSONDecodeError:
        pass  # Not JSON, try plain text
    
    # Plain text format (one seed per line)
    with open(seed_path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def auto_find_files(rule_name: str, base_dir: Path) -> tuple:
    """
    Auto-discover grammar and seeds files based on rule name
    
    Example:
        rule_name = "apt29_powershell_bypass"
        → grammar: conf/grammars/apt29_powershell_bypass.v2.json
        → seeds: conf/seeds/apt29_powershell_bypass_seeds.txt
    """
    grammar_dir = base_dir / "conf" / "grammars"
    seeds_dir = base_dir / "conf" / "seeds"
    
    # Try to find grammar file
    grammar_patterns = [
        grammar_dir / f"{rule_name}.v2.json",
        grammar_dir / f"{rule_name}.json",
    ]
    
    grammar_file = None
    for pattern in grammar_patterns:
        if pattern.exists():
            grammar_file = pattern
            break
    
    if not grammar_file:
        raise FileNotFoundError(f"Grammar file not found for rule '{rule_name}' in {grammar_dir}")
    
    # Try to find seeds file
    seed_patterns = [
        seeds_dir / f"{rule_name}_seeds.txt",
        seeds_dir / f"{rule_name}_seeds.json",
        seeds_dir / f"{rule_name}.txt",
    ]
    
    seed_file = None
    for pattern in seed_patterns:
        if pattern.exists():
            seed_file = pattern
            break
    
    return grammar_file, seed_file


def list_available_rules(base_dir: Path):
    """List all available rules in conf/grammars/"""
    grammar_dir = base_dir / "conf" / "grammars"
    
    print("\n[*] Available Rules:")
    print("=" * 80)
    
    for grammar_file in sorted(grammar_dir.glob("*.json")):
        try:
            grammar = load_grammar(grammar_file)
            name = grammar.get("meta", {}).get("name", "N/A")
            rule_id = grammar.get("meta", {}).get("rule_id", "N/A")
            desc = grammar.get("meta", {}).get("description", "No description")
            
            print(f"\nRule: {name}")
            print(f"  ID: {rule_id}")
            print(f"  Description: {desc}")
            print(f"  File: {grammar_file.name}")
        except Exception as e:
            print(f"\n[ERROR] Failed to load {grammar_file.name}: {e}")
    
    print("\n" + "=" * 80)


def main():
    parser = argparse.ArgumentParser(
        description="Universal SIEM Rule Fuzzer with Gemini",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Traditional fuzzing only
  python scripts/fuzz.py -r win_net_start_service -n 100

  # LLM-enhanced fuzzing with Gemini Flash (fast & cheap)
  python scripts/fuzz.py -r apt29_powershell_bypass -n 50 --use-llm

  # Use Gemini Pro (more capable, slower)
  python scripts/fuzz.py -r apt29_powershell_bypass -n 30 --use-llm --llm-model gemini-2.5-pro

  # Heavy LLM usage (80% LLM mutations)
  python scripts/fuzz.py -r apt29_powershell_bypass -n 30 --use-llm --llm-rate 0.8
        """
    )
    
    # Input options
    input_group = parser.add_mutually_exclusive_group(required=False)
    input_group.add_argument("-g", "--grammar", type=Path, help="Path to grammar JSON file")
    input_group.add_argument("-r", "--rule", type=str, help="Rule name (auto-discover files)")
    
    parser.add_argument("-s", "--seeds", type=Path, help="Path to seeds file")
    parser.add_argument("-n", "--num", type=int, default=50, help="Number of payloads to generate (default: 50)")
    parser.add_argument("-o", "--output", type=Path, help="Output JSON file for results")
    parser.add_argument("--list-rules", action="store_true", help="List all available rules")
    
    # Fuzzing parameters
    parser.add_argument("--epsilon-seed", type=float, help="Override epsilon for seed selection")
    parser.add_argument("--epsilon-group", type=float, help="Override epsilon for operator group selection")
    parser.add_argument("--max-mutations", type=int, help="Override max mutations per payload")
    
    # LLM parameters
    parser.add_argument("--use-llm", action="store_true", help="Enable LLM-enhanced mutations")
    parser.add_argument("--llm-model", type=str, default="gemini-2.5-flash", 
                        choices=["gemini-2.5-flash", "gemini-2.5-pro", "gemini-2.0-flash", "gemini-3-flash", "gemini-3-pro"],
                        help="Gemini model (default: gemini-2.5-flash)")
    parser.add_argument("--llm-rate", type=float, default=0.3,
                        help="Percentage of mutations using LLM (0.0-1.0, default: 0.3)")
    
    args = parser.parse_args()
    
    project_root = Path(__file__).parent.parent
    
    # Handle --list-rules
    if args.list_rules:
        list_available_rules(project_root)
        return
    
    # Validate input
    if not args.grammar and not args.rule:
        parser.error("Either --grammar or --rule must be specified (or use --list-rules)")
    
    # Resolve grammar and seeds files
    if args.rule:
        print(f"[*] Auto-discovering files for rule: {args.rule}")
        grammar_file, seed_file = auto_find_files(args.rule, project_root)
        print(f"    Grammar: {grammar_file.relative_to(project_root)}")
        if seed_file:
            print(f"    Seeds: {seed_file.relative_to(project_root)}")
    else:
        grammar_file = args.grammar
        seed_file = args.seeds
    
    # Load grammar
    print(f"\n[*] Loading grammar: {grammar_file.name}")
    grammar = load_grammar(grammar_file)
    
    # Override parameters if specified
    if args.epsilon_seed is not None:
        grammar["sampling"]["epsilon_seed"] = args.epsilon_seed
    if args.epsilon_group is not None:
        grammar["sampling"]["epsilon_group"] = args.epsilon_group
    if args.max_mutations is not None:
        grammar["mutation_engine"]["max_mutations"] = args.max_mutations
    
    # Load seeds
    custom_seeds = None
    if seed_file:
        custom_seeds = load_seeds(seed_file)
        if custom_seeds:
            print(f"[*] Loaded {len(custom_seeds)} seeds")
            print(f"[*] Sample seeds:")
            for i, seed in enumerate(custom_seeds[:3], 1):
                print(f"    {i}. {seed}")
    
    # Display rule info
    meta = grammar.get("meta", {})
    print(f"\n[*] Target Rule: {meta.get('name', 'N/A')}")
    print(f"[*] Rule ID: {meta.get('rule_id', 'N/A')}")
    print(f"[*] Description: {meta.get('description', 'N/A')}")
    print(f"[*] Max Payload Length: {meta.get('max_payload_len', 'N/A')}")
    print(f"[*] Fuzzing Parameters:")
    print(f"    - Payloads to generate: {args.num}")
    print(f"    - Max mutations: {grammar['mutation_engine']['max_mutations']}")
    print(f"    - Epsilon (seed): {grammar['sampling']['epsilon_seed']}")
    print(f"    - Epsilon (group): {grammar['sampling']['epsilon_group']}")

    
    # Initialize generator with custom seeds
    gen = PayloadGenerator(
        grammar, 
        custom_seeds=custom_seeds,
        use_llm=args.use_llm,
        llm_rate=args.llm_rate,
        llm_model=args.llm_model
    )
    
    # Run fuzzing
    print(f"\n[*] Starting fuzzing campaign...")
    print("=" * 80)
    
    results = gen.run_batch(n=args.num)
    
    # Statistics
    print("\n" + "=" * 80)
    print("[*] FUZZING RESULTS")
    print("=" * 80)
    
    total = len(results)
    valid = sum(1 for r in results if r["valid"])
    undetected = sum(1 for r in results if not r["detected"])
    successful = sum(1 for r in results if r["valid"] and not r["detected"])
    
    print(f"Total payloads: {total}")
    print(f"Valid payloads: {valid} ({valid/total*100:.1f}%)")
    print(f"Undetected: {undetected} ({undetected/total*100:.1f}%)")
    print(f"Successful bypasses: {successful} ({successful/total*100:.1f}%)")
    
    # Top successful payloads
    if successful > 0:
        print("\n[*] TOP 5 SUCCESSFUL BYPASSES:")
        successful_payloads = [r for r in results if r["valid"] and not r["detected"]]
        successful_payloads.sort(key=lambda x: x["reward"], reverse=True)
        
        for i, r in enumerate(successful_payloads[:5], 1):
            print(f"\n{i}. Reward: {r['reward']:.3f}")
            print(f"   Payload: {r['payload']}")
            print(f"   Groups: {', '.join(r['applied_groups']) if r['applied_groups'] else 'none'}")
    
    # Save results
    if args.output:
        output_file = args.output
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        rule_name = grammar_file.stem
        output_file = project_root / "data" / "results" / f"{rule_name}_{timestamp}.json"
    
    output_file.parent.mkdir(parents=True, exist_ok=True)

    
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump({
            "meta": {
                "rule": meta.get("rule_id"),
                "grammar_file": str(grammar_file),
                "seed_file": str(seed_file) if seed_file else None,
                "timestamp": datetime.now().isoformat(),
                "total": total,
                "valid": valid,
                "undetected": undetected,
                "successful": successful
            },
            "results": results
        }, f, indent=2)
    
    print(f"\n[*] Results saved to: {output_file}")


if __name__ == "__main__":
    main()