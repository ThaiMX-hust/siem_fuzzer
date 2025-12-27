# src/fuzzer/siem_client.py
import time
import subprocess
from typing import Dict
from opensearchpy import OpenSearch
from .validator import canonicalize_payload, normalize_spaces

class OpenSearchClient:
    def __init__(self, grammar: Dict, host: str, auth: tuple):
        # Kết nối đến OpenSearch
        self.client = OpenSearch(
            hosts=[{'host': host, 'port': 9200}],
            http_compress=True,
            http_auth=auth,
            use_ssl=True,
            verify_certs=False,
            ssl_show_warn=False
        )
        self.index_pattern = "wazuh-alerts-*" # Ví dụ index chứa alerts

    def _execute_payload(self, payload: str):
        """
        Thực thi payload trên máy test để sinh log gửi về SIEM.
        LƯU Ý: Cần chạy trong môi trường Sandbox/VM an toàn.
        """
        try:
            # Ví dụ thực thi lệnh (DANGER: Chỉ chạy trong sandbox)
            # subprocess.run(payload, shell=True, timeout=5)
            print(f"[EXECUTOR] Running: {payload}")
            pass 
        except Exception as e:
            print(f"Execution error: {e}")

    def _query_detection(self, payload: str) -> bool:
        """
        Query OpenSearch để xem payload vừa chạy có sinh ra alert không
        """
        # Chờ một chút để log được đẩy về OpenSearch (Latency)
        time.sleep(2) 
        
        # Query DSL: Tìm alert chứa payload trong 1 phút gần nhất
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"match_phrase": {"data.win.system.message": payload}}, # Field tùy chỉnh theo log source
                        {"range": {"@timestamp": {"gte": "now-1m"}}}
                    ]
                }
            }
        }

        response = self.client.search(
            body=query,
            index=self.index_pattern
        )
        
        # Nếu có hit (kết quả) nghĩa là bị detect
        return response['hits']['total']['value'] > 0

    def analyze(self, payload: str) -> Dict:
        """
        Hàm chính được Generator gọi
        """
        # 1. Thực thi payload
        self._execute_payload(payload)

        # 2. Query SIEM lấy feedback
        detected = self._query_detection(payload)

        # 3. Tính similarity (Logic nội bộ, không cần SIEM)
        can = canonicalize_payload(payload)
        sim = 1.0 if can == normalize_spaces(payload) else 0.5

        return {
            "detected": detected,
            "similarity": sim,
            "canonical": can
        }