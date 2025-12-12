# tests/test_generator.py
from src.fuzzer.grammar_loader import load_and_validate
from src.fuzzer.generator import PayloadGenerator

def test_generate_batch_runs():
    g = load_and_validate()
    gen = PayloadGenerator(g)
    logs = gen.run_batch(5)
    assert len(logs) == 5
    # ensure payload strings present
    for l in logs:
        assert "payload" in l and isinstance(l["payload"], str)
