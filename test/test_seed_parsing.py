import pytest
from src.fuzzer.generator import PayloadGenerator

def test_parse_simple_seed(sample_grammar):
    gen = PayloadGenerator(sample_grammar)
    
    # Test canonical parse
    core, mode = gen.build_core_from_seed("net.exe start Spooler")
    assert mode == "canonical"
    assert "net.exe" in core and "Spooler" in core

def test_wrapper_detection(sample_grammar):
    gen = PayloadGenerator(sample_grammar)
    
    # Should detect wrapper
    core, mode = gen.build_core_from_seed('cmd.exe /c "net.exe start Spooler"')
    assert mode == "override"
    assert core == 'cmd.exe /c "net.exe start Spooler"'

def test_case_insensitive_parse(sample_grammar):
    gen = PayloadGenerator(sample_grammar)
    
    core, mode = gen.build_core_from_seed("NET.EXE START SPOOLER")
    assert mode == "canonical"

def test_fallback_generation(sample_grammar):
    gen = PayloadGenerator(sample_grammar)
    
    # Invalid seed → fallback
    core, mode = gen.build_core_from_seed("random gibberish")
    assert mode == "fallback"
    assert gen._matches_constraints(core)

def test_template_token_parsing(sample_grammar):
    gen = PayloadGenerator(sample_grammar)
    
    # <service> template should match any arg
    core, mode = gen.build_core_from_seed("sc.exe start CustomService")
    assert mode == "canonical"
    assert "CustomService" in core