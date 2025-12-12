# src/fuzzer/validator.py
import re
from typing import Dict

def normalize_spaces(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()

def canonicalize_payload(p: str) -> str:
    s = p
    s = re.sub(r"(&::|;|\|\|)+\s*$", "", s)
    s = s.replace("^", "")
    s = s.replace('"', "").replace("'", "")
    s = normalize_spaces(s)
    return s

class Validator:
    def __init__(self, grammar: Dict):
        rules = grammar["rules"]["payload_core"]
        self.keyword = rules["constraints"].get("must_contain_keyword")
        self.regex_positive = re.compile(rules["constraints"].get("regex_positive"))

    def quick_check(self, core: str) -> bool:
        if self.keyword and self.keyword not in core:
            return False
        if len(core.strip()) == 0:
            return False
        return True

    def full_check(self, payload: str, max_len: int) -> bool:
        if len(payload) > max_len:
            return False
        if self.keyword and self.keyword not in payload:
            return False
        can = canonicalize_payload(payload)
        if not self.regex_positive.search(can):
            return False
        if payload.count('"') % 2 != 0:
            return False
        return True
