from opensearchpy import OpenSearch
import time
import warnings
from opensearchpy.exceptions import OpenSearchWarning

# Tắt cảnh báo SSL không an toàn (nếu dùng self-signed cert)
warnings.filterwarnings('ignore', category=OpenSearchWarning)
warnings.filterwarnings('ignore', category=UserWarning)

# --- CẤU HÌNH ---
OPENSEARCH_HOST = '192.168.150.21'
AUTH = ('admin', 'Bkcs@2025@2025') # Điền user/pass của bạn
INDEX_NAME = 'winlogbeat-*'
# Từ khóa "Mồi" bạn vừa chạy ở Bước 1
TARGET_KEYWORD = "BAT_DAU_KIEM_TRA_SIEM_INTEGRATION_123" 

# Kết nối OpenSearch
client = OpenSearch(
    hosts=[{'host': OPENSEARCH_HOST, 'port': 9200}],
    http_auth=AUTH,
    use_ssl=True,
    verify_certs=False,
    ssl_show_warn=False
)

def verify_log_arrival():
    print(f"[*] Đang tìm kiếm lệnh chứa: '{TARGET_KEYWORD}' trong 5 phút gần nhất...")
    
    # Query DSL
    query_body = {
        "query": {
            "bool": {
                "must": [
                    # Điều kiện 1: Event ID 1 (Process Creation)
                    { "match": { "winlog.event_id": 1 } },
                    
                    # Điều kiện 2: Tìm chính xác cụm từ trong CommandLine
                    # Dùng match_phrase để tìm cụm từ thay vì từng từ đơn lẻ
                    { "match_phrase": { 
                        "winlog.event_data.CommandLine": TARGET_KEYWORD 
                    }}
                ],
                "filter": [
                    {
                        "range": {
                            "@timestamp": {
                                # Chỉ tìm trong 5 phút qua
                                "gte": "now-5m", 
                                "lt": "now"
                            }
                        }
                    }
                ]
            }
        }
    }

    # Gửi query
    try:
        response = client.search(body=query_body, index=INDEX_NAME)
        hits = response['hits']['hits']
        
        if len(hits) > 0:
            print(f"\n[+] THÀNH CÔNG! Tìm thấy {len(hits)} log khớp lệnh vừa chạy.")
            print("-" * 50)
            for hit in hits:
                source = hit['_source']
                # Lấy dữ liệu an toàn (tránh lỗi nếu key thiếu)
                cmd_line = source.get('winlog', {}).get('event_data', {}).get('CommandLine', 'N/A')
                timestamp = source.get('@timestamp')
                computer = source.get('winlog', {}).get('computer_name', 'Unknown')
                
                print(f"   Thời gian: {timestamp}")
                print(f"   Máy nguồn: {computer}")
                print(f"   Command  : {cmd_line}")
            print("-" * 50)
            return True
        else:
            print("[-] Chưa tìm thấy log nào. (Log có thể chưa được đẩy về kịp)")
            return False

    except Exception as e:
        print(f"[!] Lỗi khi query: {e}")
        return False

# Vòng lặp kiểm tra (Retries)
# Vì Winlogbeat thường đẩy log sau vài giây đến 1 phút
print("[*] Bắt đầu vòng lặp kiểm tra (tối đa 60s)...")
for i in range(6):
    if verify_log_arrival():
        break
    print(f"    -> Đợi 10s rồi thử lại lần {i+1}...")
    time.sleep(10)
else:
    print("\n[X] QUÁ THỜI GIAN: Không tìm thấy log sau 60s. Kiểm tra lại Winlogbeat service.")