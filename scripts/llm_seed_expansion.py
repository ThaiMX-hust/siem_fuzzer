"""
Use Gemini to generate creative seed variants
"""
import os
import google.generativeai as genai
from pathlib import Path
from dotenv import load_dotenv

def expand_seeds_with_llm(base_seeds: list, rule_name: str, target_count: int = 50) -> list:
    """Use LLM to generate creative variants"""
    
    load_dotenv()
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        print("[!] GEMINI_API_KEY not found")
        return []
    
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel("gemini-1.5-flash")
    
    prompt = f"""You are a Windows command obfuscation expert.

Given these base commands for SIEM rule '{rule_name}':
{chr(10).join(f"- {seed}" for seed in base_seeds[:3])}

Generate {target_count} diverse obfuscated variants using:
1. **Insertion**: Insert characters (quotes, carets, spaces)
2. **Substitution**: Replace flags with long forms (-ep → -ExecutionPolicy)
3. **Omission**: Remove .exe, paths, optional args
4. **Reordering**: Change argument order
5. **Recoding**: Encode IPs (127.0.0.1 → 2130706433), hex values
6. **Traditional**: Caret ^, case MiXinG, environment variables %ComSpec%

Requirements:
- All commands MUST be valid and executable on Windows
- Maintain original functionality
- Be diverse (don't repeat patterns)
- Include hybrid combinations

Return as newline-separated list, NO explanations:
"""
    
    try:
        response = model.generate_content(
            prompt,
            generation_config={"temperature": 0.8, "max_output_tokens": 1000},
            safety_settings=[
                {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"}
            ]
        )
        
        seeds = [line.strip() for line in response.text.split('\n') if line.strip()]
        return seeds
    
    except Exception as e:
        print(f"[!] LLM expansion failed: {e}")
        return []

def main():
    """Expand all seed files with LLM"""
    seeds_dir = Path(__file__).parent.parent / "conf" / "seeds"
    
    for seed_file in seeds_dir.glob("*.txt"):
        rule_name = seed_file.stem
        
        # Read existing seeds
        with open(seed_file, 'r', encoding='utf-8') as f:
            base_seeds = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        if not base_seeds:
            continue
        
        print(f"\n[*] Expanding seeds for {rule_name} (current: {len(base_seeds)})")
        
        # Generate new seeds
        new_seeds = expand_seeds_with_llm(base_seeds, rule_name, target_count=30)
        
        if new_seeds:
            # Combine and deduplicate
            all_seeds = list(dict.fromkeys(base_seeds + new_seeds))
            
            # Save
            backup_file = seed_file.with_suffix('.txt.bak')
            seed_file.rename(backup_file)
            
            with open(seed_file, 'w', encoding='utf-8') as f:
                f.write(f"# Enhanced seeds for {rule_name}\n")
                f.write(f"# LLM-expanded collection\n")
                f.write(f"# Total: {len(all_seeds)} seeds\n\n")
                
                for seed in all_seeds:
                    f.write(f"{seed}\n")
            
            print(f"[+] Expanded to {len(all_seeds)} seeds (backup: {backup_file})")

if __name__ == "__main__":
    main()