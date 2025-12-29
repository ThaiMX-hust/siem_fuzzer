# src/fuzzer/siem_client.py
import time
import urllib3
from typing import Dict
from opensearchpy import OpenSearch
from .validator import canonicalize_payload, normalize_spaces

# Disable certificate warnings (for self-signed lab certs)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class RealSiemClient:
    def __init__(self, grammar: Dict, host="192.168.150.21", port=9200, auth=None):
        
        if auth is None:
            auth = ("admin", "Bkcs@2025@2025")

        # Connect to OpenSearch
        self.client = OpenSearch(
            hosts=[{'host': host, 'port': port}],
            http_compress=True,
            http_auth=auth,
            use_ssl=True,
            verify_certs=False,
            ssl_show_warn=False
        )
        # Index pattern
        self.index_pattern = "winlogbeat-*"
        
        # Regex 
        self.regex_positive = grammar.get("rules", {}).get("payload_core", {}).get("constraints", {}).get("regex_positive")

    def analyze(self, payload: str) -> Dict:
        """
        Query OpenSearch xem payload có xuất hiện trong log không.
        """
        # --- QUERY ---
        query = {
            "query": {
                "bool": {
                    "must": [
                        # Event ID 1: Process Creation
                        {"match": {"winlog.event_id": 1}},
                        # Match exact payload in CommandLine
                        {"match_phrase": {"winlog.event_data.CommandLine": payload}}, 
                        # Search within the last 1 minute 
                        {"range": {"@timestamp": {"gte": "now-1m"}}}
                    ]
                }
            }
        }

        detected = False
        # --- OPTIMIZE RETRY LOOP ---
        # Try 6 times, each time wait 5s => Total max wait 30s
        # Winlogbeat usually takes 5-10s to push logs.
        for i in range(6):
            try:
                # Sleep before query to give system time to catch up
                time.sleep(5) 
                
                response = self.client.search(body=query, index=self.index_pattern)
                hits = response['hits']['total']['value']
                
                if hits > 0:
                    detected = True
                    # print(f"[+] Log Found at attempt {i+1}") # Uncomment to debug
                    break
                    
            except Exception as e:
                print(f"[!] OpenSearch Query Error (Attempt {i+1}): {e}")
                detected = False

        # --- SCORING LOGIC (REWARD) ---
        can = canonicalize_payload(payload)
        
        # Scoring logic:
        # - detected = True (Caught) -> Similarity = 1.0 (Heavy penalty / Ineffective)
        # - detected = False (Bypass) -> Similarity = low (Good)
        sim = 1.0 if detected else (1.0 if can == normalize_spaces(payload) else 0.5)
        
        return {
            "detected": detected, 
            "similarity": sim, 
            "canonical": can,
            "raw_payload": payload
        }