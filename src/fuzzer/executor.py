# src/fuzzer/executor.py
import subprocess
import time
import signal

class PayloadExecutor:
    def __init__(self, timeout=8):
        self.timeout = timeout

    def execute(self, cmd: str) -> dict:
        """
        Thực thi lệnh trên máy cục bộ và trả về kết quả
        """
        try:
            # Sử dụng CREATE_NEW_PROCESS_GROUP để dễ kill process con
            proc = subprocess.Popen(
                cmd, 
                shell=True, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
            )
            
            stdout, stderr = proc.communicate(timeout=self.timeout)
            
            return {
                "success": proc.returncode == 0,
                "returncode": proc.returncode,
                "stdout": stdout,
                "stderr": stderr
            }
            
        except subprocess.TimeoutExpired:
            # Kill process nếu treo
            proc.send_signal(signal.CTRL_BREAK_EVENT)
            time.sleep(1)
            proc.kill()
            return {
                "success": False,
                "returncode": -1,
                "stdout": "",
                "stderr": "TimeoutExpired"
            }
        except Exception as e:
            return {
                "success": False,
                "returncode": -1,
                "stdout": "",
                "stderr": str(e)
            }