import pytest
from src.fuzzer.generator import PayloadGenerator
import json
from pathlib import Path

def test_apt29_structures():
    """Test APT29 grammar with structures"""
    grammar_path = Path(__file__).parent.parent / "conf" / "grammars" / "apt29_powershell_bypass.v1.json"
    with open(grammar_path, "r") as f:
        grammar = json.load(f)
    
    gen = PayloadGenerator(grammar)
    
    # Test generation
    canonical = gen._generate_canonical_from_grammar()
    print(f"Generated: {canonical}")
    
    assert gen._matches_constraints(canonical)
    assert "powershell" in canonical.lower()
    assert "-noni" in canonical.lower()
    assert "-ep" in canonical.lower()
    assert "bypass" in canonical.lower()
    assert "$" in canonical

def test_win_net_structures():
    """Test win_net_start_service grammar with structures"""
    grammar_path = Path(__file__).parent.parent / "conf" / "grammars" / "win_net_start_service.v1.json"
    with open(grammar_path, "r") as f:
        grammar = json.load(f)
    
    gen = PayloadGenerator(grammar)
    
    # Test parsing seed
    core, mode = gen.build_core_from_seed("net.exe start Spooler")
    assert mode == "canonical"
    assert "net.exe" in core
    assert "Spooler" in core
    
    # Test generation
    canonical = gen._generate_canonical_from_grammar()
    print(f"Generated: {canonical}")
    
    assert gen._matches_constraints(canonical)
    assert " start " in canonical