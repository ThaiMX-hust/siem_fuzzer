import pytest
import os
from src.fuzzer.llm_mutator import LLMMutator

@pytest.fixture
def llm_mutator():
    """Fixture for LLM mutator (requires API key)"""
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        pytest.skip("GEMINI_API_KEY not set")
    
    return LLMMutator(model="gemini-1.5-flash", use_cache=True)

def test_llm_mutation_basic(llm_mutator):
    """Test basic LLM mutation"""
    payload = "net.exe start Spooler"
    target_rule = "win_net_start_service"
    
    mutated = llm_mutator.mutate_payload(payload, target_rule, [])
    
    assert mutated is not None
    assert len(mutated) > 0
    assert mutated != payload
    # Check if obfuscation was applied
    assert ("^" in mutated or mutated != payload.lower())

def test_llm_mutation_with_history(llm_mutator):
    """Test LLM mutation with history for diversity"""
    payload = "net.exe start Spooler"
    target_rule = "win_net_start_service"
    history = [
        "n^et.exe start Spooler",
        "NET.EXE start Spooler"
    ]
    
    mutated = llm_mutator.mutate_payload(payload, target_rule, history)
    
    assert mutated is not None
    assert mutated not in history

def test_llm_cache(llm_mutator):
    """Test caching mechanism"""
    payload = "sc.exe start W32Time"
    target_rule = "win_net_start_service"
    
    # First call
    result1 = llm_mutator.mutate_payload(payload, target_rule, [])
    api_calls_1 = llm_mutator.stats["api_calls"]
    
    # Second call (should hit cache)
    result2 = llm_mutator.mutate_payload(payload, target_rule, [])
    api_calls_2 = llm_mutator.stats["api_calls"]
    
    assert result1 == result2
    assert api_calls_2 == api_calls_1

def test_llm_fallback(llm_mutator):
    """Test fallback on error"""
    payload = "net.exe start Spooler"
    
    result = llm_mutator.mutate_payload(
        payload, 
        "test_rule", 
        [],
        fallback_on_error=True
    )
    
    assert result is not None