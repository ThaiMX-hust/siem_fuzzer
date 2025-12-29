# src/fuzzer/siem_client.py
import time
import urllib3
from typing import Dict
from opensearchpy import OpenSearch
from .validator import canonicalize_payload, normalize_spaces

# Tắt cảnh báo certificate (cho lab self-signed)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class RealSiemClient:
    def __init__(self, grammar: Dict, host="192.168.150.21", port=9200, auth=("admin", "Bkcs@2025@2025")):
        # Kết nối OpenSearch
        self.client = OpenSearch(
            hosts=[{'host': host, 'port': port}],
            http_compress=True,
            http_auth=auth,
            use_ssl=True,
            verify_certs=False,
            ssl_show_warn=False
        )
        # Index pattern của bạn (winlogbeat-*)
        self.index_pattern = "winlogbeat-*"
        
        # Regex phụ trợ (nếu cần dùng để tính similarity)
        self.regex_positive = grammar.get("rules", {}).get("payload_core", {}).get("constraints", {}).get("regex_positive")

    def analyze(self, payload: str) -> Dict:
        """
        Query OpenSearch xem payload có xuất hiện trong log không.
        """
        # --- QUERY ĐÃ ĐIỀU CHỈNH THEO FIELD CỦA BẠN ---
        query = {
            "query": {
                "bool": {
                    "must": [
                        # Tìm chính xác chuỗi payload trong trường Command Line của Windows Log
                        {"match_phrase": {"winlog.event_data.CommandLine": payload}}, 
                        # Chỉ tìm trong 15s gần nhất để tránh log cũ
                        {"range": {"@timestamp": {"gte": "now-15s"}}}
                    ]
                }
            }
        }

        detected = False
        try:
            # Retry 3 lần (tổng ~6s) để chờ log được index
            for _ in range(3):
                response = self.client.search(body=query, index=self.index_pattern)
                hits = response['hits']['total']['value']
                
                if hits > 0:
                    detected = True
                    break
                
                time.sleep(2) # Đợi 2s rồi thử lại
        except Exception as e:
            print(f"[!] OpenSearch Query Error: {e}")
            detected = False

        # Tính toán các chỉ số khác cho thuật toán Bandit
        can = canonicalize_payload(payload)
        # Nếu bị detect -> Sim = 1.0 (để phạt), nếu không -> tính sim dựa trên biến đổi chuỗi
        sim = 1.0 if detected else (1.0 if can == normalize_spaces(payload) else 0.5)
        
        return {"detected": detected, "similarity": sim, "canonical": can}