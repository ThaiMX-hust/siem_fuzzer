import pytest
import subprocess
from unittest.mock import MagicMock, patch
from src.fuzzer.executor import LocalExecutor
from src.fuzzer.siem_client import RealSiemClient
from src.fuzzer.generator import PayloadGenerator

# ==========================================
# 1. Test LocalExecutor
# ==========================================

@patch("subprocess.run")
def test_local_executor_success(mock_run):
    """Test trường hợp chạy lệnh thành công"""
    executor = LocalExecutor()
    payload = "echo test"
    
    # Giả lập subprocess.run chạy thành công
    mock_run.return_value.returncode = 0
    
    result = executor.run(payload)
    
    assert result is True
    # Kiểm tra xem có đúng là gọi powershell không
    args, kwargs = mock_run.call_args
    cmd_list = args[0]
    assert cmd_list[0] == "powershell"
    assert payload in cmd_list

@patch("subprocess.run")
def test_local_executor_timeout(mock_run):
    """Test trường hợp lệnh bị treo (Timeout)"""
    executor = LocalExecutor()
    
    # Giả lập ném ra exception TimeoutExpired
    mock_run.side_effect = subprocess.TimeoutExpired(cmd="test", timeout=10)
    
    result = executor.run("sleep 100")
    assert result is False

# ==========================================
# 2. Test RealSiemClient
# ==========================================

@patch("src.fuzzer.siem_client.OpenSearch")
def test_siem_client_detected(mock_opensearch_cls):
    """Test trường hợp OpenSearch tìm thấy log (Detected)"""
    # Setup mock client
    mock_client_instance = mock_opensearch_cls.return_value
    
    # Giả lập phản hồi từ OpenSearch: hits > 0
    mock_client_instance.search.return_value = {
        "hits": {
            "total": {"value": 1}
        }
    }
    
    siem = RealSiemClient()
    result = siem.analyze("test_payload")
    
    assert result["detected"] is True
    assert result["similarity"] == 1.0
    # Đảm bảo search được gọi với đúng index
    mock_client_instance.search.assert_called()

@patch("src.fuzzer.siem_client.OpenSearch")
def test_siem_client_missed(mock_opensearch_cls):
    """Test trường hợp không thấy log (Bypassed/Missed)"""
    mock_client_instance = mock_opensearch_cls.return_value
    
    # Giả lập hits = 0
    mock_client_instance.search.return_value = {
        "hits": {
            "total": {"value": 0}
        }
    }
    
    siem = RealSiemClient()
    result = siem.analyze("silent_payload")
    
    assert result["detected"] is False

# ==========================================
# 3. Test Integration (Generator Flow)
# ==========================================

@patch("src.fuzzer.generator.time.sleep") # Mock sleep để test chạy nhanh
@patch("src.fuzzer.generator.RealSiemClient")
@patch("src.fuzzer.generator.LocalExecutor")
def test_generator_full_flow_detected(mock_executor_cls, mock_siem_cls, mock_sleep, sample_grammar):
    """
    Test toàn bộ luồng: Sinh Payload -> Chạy Exec -> Đợi -> Check SIEM
    """
    # 1. Setup Mock Executor
    mock_executor = mock_executor_cls.return_value
    mock_executor.run.return_value = True

    # 2. Setup Mock SIEM (Giả lập là bị detect)
    mock_siem = mock_siem_cls.return_value
    mock_siem.analyze.return_value = {"detected": True, "similarity": 1.0}

    # 3. Init Generator
    gen = PayloadGenerator(sample_grammar)
    
    # Override param để test nhanh
    gen.eps_seed = 0.0 # Force exploit mode
    
    # 4. Run
    result = gen.generate_one()

    # 5. Assertions (Kiểm tra logic hoạt động đúng không)
    assert result["valid"] is True
    
    # Kiểm tra Executor đã được gọi
    mock_executor.run.assert_called_once()
    
    # Kiểm tra đã sleep (đợi log) chưa
    mock_sleep.assert_called() 
    
    # Kiểm tra SIEM đã được query chưa
    mock_siem.analyze.assert_called_once()
    
    # Kiểm tra kết quả trả về
    assert result["detected"] is True
    # Nếu detected thì reward thường thấp hoặc âm (tùy config reward engine)
    # Ở đây ta chỉ check nó có tính toán reward
    assert "reward" in result

@patch("src.fuzzer.generator.time.sleep")
@patch("src.fuzzer.generator.RealSiemClient")
@patch("src.fuzzer.generator.LocalExecutor")
def test_generator_bypass_success(mock_executor_cls, mock_siem_cls, mock_sleep, sample_grammar):
    """
    Test luồng Bypass thành công: Valid payload + Không detect
    """
    # Mock chạy OK
    mock_executor_cls.return_value.run.return_value = True
    
    # Mock SIEM KHÔNG tìm thấy (Bypass!)
    mock_siem_cls.return_value.analyze.return_value = {"detected": False, "similarity": 0.5}

    gen = PayloadGenerator(sample_grammar)
    result = gen.generate_one()

    assert result["valid"] is True
    assert result["detected"] is False
    
    # Kiểm tra xem payload có được lưu vào danh sách thành công không
    assert len(gen.corpus_successful) > 0