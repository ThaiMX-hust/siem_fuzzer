# src/fuzzer/operator_registry.py
import re
import random
from typing import Dict, List, Tuple

class Operator:
    """
    Operator represents a single obfuscation or mutation technique.

    Each operator contains:
    - name   : identifier of the operator
    - sample : example pattern used as a heuristic hint
               to decide how the operator should be applied
    """
    def __init__(self, name: str, sample: str):
        self.name = name
        self.sample = sample

class OperatorGroup:
    """
    OperatorGroup represents a group of related operators
    sharing the same obfuscation strategy.

    This class also stores bandit-related statistics
    for group-level learning.
    """
    def __init__(self, name: str, operators: List[Operator]):
        self.name = name
        self.operators = operators
        self.q_g = 0.1
        self.n_g = 0

class OperatorRegistry:
    """
    OperatorRegistry manages all operator groups and
    applies selected operators to core payloads.

    It acts as the mutation engine of the fuzzer.
    """
    def __init__(self, grammar: dict, rng_seed=42):
        self.rng = random.Random(rng_seed)
        self.groups: Dict[str, OperatorGroup] = {}
        for gname, gdef in grammar.get("obfuscation_groups", {}).items():
            ops = [Operator(op["name"], op["sample"]) for op in gdef.get("operators", [])]
            self.groups[gname] = OperatorGroup(gname, ops)
        
        # Add 5 evasion techniques
        self.evasion_techniques = {
            "insertion": self._apply_insertion,
            "substitution": self._apply_substitution,
            "omission": self._apply_omission,
            "reordering": self._apply_reordering,
            "recoding": self._apply_recoding
        }
    
    def list_groups(self) -> List[str]:
        return list(self.groups.keys())

    def choose_operator_from_group(self, group_name: str) -> Operator:
        g = self.groups[group_name]
        return self.rng.choice(g.operators)

    def _apply_insertion(self, payload: str) -> str:
        """
        Insert characters between critical keywords
        Examples:
        - schtasks /create → schtasks /"create"
        - net start → net /"start"
        """
        # Target critical keywords from grammar
        keywords = ["create", "start", "stop", "delete", "config"]
        
        for kw in keywords:
            if kw in payload.lower():
                # Insert quotes or extra characters
                patterns = [
                    (kw, f'/"{kw}"'),           # /create → /"create"
                    (kw, f'/{kw[0]}""{kw[1:]}'), # /create → /c""reate
                    (kw, f'  {kw}'),            # Extra spaces
                ]
                
                pattern, replacement = self.rng.choice(patterns)
                payload = payload.replace(pattern, replacement)
                break
        
        return payload
    
    def _apply_substitution(self, payload: str) -> str:
        """
        Replace flags/arguments with long-form equivalents
        Examples:
        - curl -O → curl --remote-name
        - powershell -ep bypass → powershell -ExecutionPolicy bypass
        """
        substitutions = {
            "-O": "--remote-name",
            "-o": "--output",
            "-ep": "-ExecutionPolicy",
            "-enc": "-EncodedCommand",
            "-w": "-WindowStyle",
            "-nop": "-NoProfile",
        }
        
        for short, long in substitutions.items():
            if short in payload:
                payload = payload.replace(short, long)
                break
        
        return payload
    
    def _apply_omission(self, payload: str) -> str:
        """
        Remove optional parts (like .exe extension)
        Examples:
        - cscript.exe → cscript
        - powershell.exe → powershell
        """
        # Remove .exe extensions
        executables = ["schtasks.exe", "net.exe", "sc.exe", "powershell.exe", 
                      "cmd.exe", "wmic.exe", "cscript.exe"]
        
        for exe in executables:
            if exe in payload.lower():
                payload = payload.replace(exe, exe.replace(".exe", ""))
                break
        
        return payload
    
    def _apply_reordering(self, payload: str) -> str:
        """
        Reorder arguments (if semantically valid)
        Examples:
        - procdump -ma lsass → procdump lsass -ma
        - net start Spooler /y → net start /y Spooler
        """
        # Simple reordering: move flags after arguments
        parts = payload.split()
        
        # Find flags (start with - or /)
        flags = [p for p in parts if p.startswith('-') or p.startswith('/')]
        non_flags = [p for p in parts if not (p.startswith('-') or p.startswith('/'))]
        
        if flags and len(non_flags) > 2:
            # Move some flags to the end
            flag_to_move = self.rng.choice(flags)
            parts.remove(flag_to_move)
            parts.append(flag_to_move)
            
            return " ".join(parts)
        
        return payload
    
    def _apply_recoding(self, payload: str) -> str:
        """
        Encode values in different representations
        Examples:
        - IP address: 127.0.0.1 → 2130706433 (decimal)
        - Port: 8080 → 0x1F90 (hex)
        """
        import re
        
        # Find IP addresses
        ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        ips = re.findall(ip_pattern, payload)
        
        for ip in ips:
            # Convert to decimal (e.g., 127.0.0.1 → 2130706433)
            octets = [int(x) for x in ip.split('.')]
            decimal = (octets[0] << 24) + (octets[1] << 16) + (octets[2] << 8) + octets[3]
            payload = payload.replace(ip, str(decimal))
            break
        
        return payload
    
    def apply_operator(self, op_name: str, payload: str) -> str:
        """Enhanced operator application with evasion techniques"""
        # Check if it's an evasion technique
        if op_name in self.evasion_techniques:
            return self.evasion_techniques[op_name](payload)
        
        # ...existing code for traditional operators...
    def _apply_evasion_technique(self, technique: str, payload: str) -> str:
        """Public method to apply evasion techniques"""
        if technique not in self.evasion_techniques:
            raise ValueError(f"Unknown evasion technique: {technique}")
        
        return self.evasion_techniques[technique](payload)
    
    def list_evasion_techniques(self) -> list:
        """List all available evasion techniques"""
        return list(self.evasion_techniques.keys())