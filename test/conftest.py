import pytest
import json
from pathlib import Path

@pytest.fixture
def sample_grammar():
    """
    Load grammar từ conf/grammars/win_net_start_service.v1.json
    Fixture này được dùng bởi tất cả test files trong thư mục test/
    """
    # Đường dẫn tương đối từ test/ lên root project
    grammar_path = Path(__file__).parent.parent / "conf" / "grammars" / "win_net_start_service.v1.json"
    
    if not grammar_path.exists():
        raise FileNotFoundError(f"Grammar file not found: {grammar_path}")
    
    with open(grammar_path, "r", encoding="utf-8") as f:
        grammar = json.load(f)
    
    return grammar


@pytest.fixture
def minimal_grammar():
    """
    Grammar tối giản để test nhanh mà không cần file thực
    """
    return {
        "meta": {
            "name": "test_grammar",
            "target_rule": "test_rule",
            "max_payload_len": 200
        },
        "terminals": {
            "executables": [
                {"tok": "test.exe", "weight": 1.0}
            ],
            "arguments": [
                {"tok": "<arg>", "examples": ["arg1", "arg2"], "weight": 1.0}
            ],
            "wrappers": [
                {"fmt": "{}", "weight": 1.0}
            ]
        },
        "obfuscation_groups": {},
        "rules": {
            "payload_core": {
                "structure": [
                    {"type": "choose", "from": "executables"},
                    {"type": "sep", "tok": " "},
                    {"type": "literal", "tok": "run"},
                    {"type": "sep", "tok": " "},
                    {"type": "choose", "from": "arguments"}
                ],
                "constraints": {
                    "must_contain_keyword": " run "
                }
            }
        },
        "mutation_engine": {
            "max_mutations": 2,
            "preserve_keyword": True
        },
        "sampling": {
            "epsilon_seed": 0.1,
            "epsilon_group": 0.1
        }
    }


@pytest.fixture
def test_seeds():
    """
    Test seeds để dùng trong các test
    """
    return [
        "net.exe start Spooler",
        "sc.exe start W32Time",
        "net1.exe start BITS"
    ]