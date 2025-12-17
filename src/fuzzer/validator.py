# src/fuzzer/validator.py
import re
from typing import Dict

def normalize_spaces(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()

def canonicalize_payload(p: str) -> str:
    """Normalize payload for comparison"""
    p = p.replace("^", "")
    p = re.sub(r"\s+", " ", p).strip()
    return p.lower()

class Validator:
    def __init__(self, grammar: Dict):
        self.grammar = grammar
        rules = grammar.get("rules", {})
        payload_core = rules.get("payload_core", {})
        constraints = payload_core.get("constraints", {})
        
        # Extract keyword constraint
        keyword = constraints.get("must_contain_keyword")
        
        # Normalize to list for uniform handling
        if keyword:
            if isinstance(keyword, str):
                self.keywords = [keyword]
            elif isinstance(keyword, list):
                self.keywords = keyword
            else:
                self.keywords = []
        else:
            self.keywords = []
        
        # Also support must_contain_all
        must_contain_all = constraints.get("must_contain_all")
        if must_contain_all:
            self.keywords.extend(must_contain_all)
        
        # Remove duplicates
        self.keywords = list(set(self.keywords))
        
        self.regex = constraints.get("regex_positive")

    def quick_check(self, core: str) -> bool:
        """
        Quick validation: check if core contains required keywords.
        Returns True if valid.
        """
        if not self.keywords:
            return True
        
        canon = canonicalize_payload(core)
        
        # Normalize for matching (handle PowerShell aliases)
        canon_norm = self._normalize_for_matching(canon)
        
        # All keywords must be present
        for keyword in self.keywords:
            if keyword not in canon_norm:
                return False
        
        return True

    def full_check(self, payload: str, max_len: int) -> bool:
        """
        Full validation: length + keywords + regex.
        Returns True if valid.
        """
        if len(payload) > max_len:
            return False
        
        canon = canonicalize_payload(payload)
        canon_norm = self._normalize_for_matching(canon)
        
        # Check keywords
        for keyword in self.keywords:
            if keyword not in canon_norm:
                return False
        
        # Check regex if present
        if self.regex:
            if not re.search(self.regex, canon, flags=re.IGNORECASE):
                return False
        
        return True
    
    def _normalize_for_matching(self, payload: str) -> str:
        """
        Normalize payload for constraint matching.
        Map command/flag aliases to canonical form.
        """
        normalized = payload.lower()
        
        # PowerShell flag aliases
        normalized = re.sub(r'-noninteractive\b', '-noni', normalized, flags=re.IGNORECASE)
        normalized = re.sub(r'-noni\b', '-noni', normalized, flags=re.IGNORECASE)
        normalized = re.sub(r'-executionpolicy\b', '-ep', normalized, flags=re.IGNORECASE)
        normalized = re.sub(r'-ep\b', '-ep', normalized, flags=re.IGNORECASE)
        
        # Windows command aliases (if needed)
        # normalized = re.sub(r'net1\.exe\b', 'net.exe', normalized, flags=re.IGNORECASE)
        
        return normalized
