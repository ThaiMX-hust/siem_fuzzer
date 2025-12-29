import urllib3
import json
from opensearchpy import OpenSearch

# Tắt cảnh báo certificate (Do chạy nội bộ self-signed)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- CẤU HÌNH ---
HOST = "192.168.150.21"
PORT = 9200
AUTH = ("admin", "Bkcs@2025@2025")
INDEX_PATTERN = "winlogbeat-*"

def main():
    print(f"[*] Đang kết nối tới OpenSearch tại https://{HOST}:{PORT}...")

    # 1. Khởi tạo Client
    try:
        client = OpenSearch(
            hosts=[{'host': HOST, 'port': PORT}],
            http_compress=True,
            http_auth=AUTH,
            use_ssl=True,
            verify_certs=False,
            ssl_show_warn=False
        )
        
        if not client.ping():
            print("[!] Lỗi: Không thể ping tới server. Kiểm tra lại IP/Port/Network.")
            return

        info = client.info()
        print(f"[+] Kết nối thành công! Server: {info['version']['distribution']} {info['version']['number']}")
        
    except Exception as e:
        print(f"[!] Lỗi kết nối nghiêm trọng: {e}")
        return

    # 2. Kiểm tra Index
    print(f"\n[*] Đang kiểm tra index '{INDEX_PATTERN}'...")
    if not client.indices.exists(index=INDEX_PATTERN):
        print(f"[!] CẢNH BÁO: Index '{INDEX_PATTERN}' không tồn tại.")
        return
    else:
        print(f"[+] Index '{INDEX_PATTERN}' tồn tại.")

    # 3. Tìm kiếm Log Process Creation (Event ID 1)
    # Đây là bước quan trọng nhất: Chỉ lấy log tạo tiến trình mới kiểm tra được Command Line
    print(f"\n[*] Đang tìm kiếm log Sysmon Process Creation (Event ID: 1)...")
    
    query = {
        "size": 1,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "must": [
                    # Lọc chính xác Event ID 1 (Sysmon) hoặc 4688 (Windows Security)
                    {"match": {"winlog.event_id": 1}}
                ]
            }
        }
    }

    try:
        response = client.search(body=query, index=INDEX_PATTERN)
        hits = response['hits']['hits']

        if len(hits) == 0:
            print("[!] CẢNH BÁO: Không tìm thấy bất kỳ log Event ID 1 nào trong Index này.")
            print("    -> Nguyên nhân: Có thể máy Victim chưa cài Sysmon hoặc chưa sinh ra log Process nào.")
            print("    -> Cách fix: Hãy vào máy Victim, mở CMD và gõ một lệnh bất kỳ (ví dụ: ipconfig) rồi chạy lại script này.")
            return

        latest_log = hits[0]['_source']
        timestamp = latest_log.get('@timestamp', 'N/A')
        print(f"[+] Tìm thấy log Process Creation mới nhất lúc: {timestamp}")

        # 4. Kiểm tra trường dữ liệu (Field Mapping)
        print("\n[*] Kiểm tra cấu trúc dữ liệu để xác định trường Command Line...")
        
        # Lấy phần data quan trọng
        win_event_data = latest_log.get('winlog', {}).get('event_data', {})
        
        # Check 1: Theo chuẩn Windows Native (như URL Kibana bạn gửi)
        cmd_line_native = win_event_data.get('CommandLine')
        
        # Check 2: Theo chuẩn ECS (đề phòng)
        cmd_line_ecs = latest_log.get('process', {}).get('command_line')

        if cmd_line_native:
            print(f"[+] THÀNH CÔNG: Tìm thấy trường 'winlog.event_data.CommandLine'")
            print(f"    -> Giá trị mẫu: {cmd_line_native}")
            print(f"    -> KẾT LUẬN: Script Fuzzer của bạn phải query vào field: 'winlog.event_data.CommandLine'")
            
        elif cmd_line_ecs:
            print(f"[+] THÀNH CÔNG: Tìm thấy trường 'process.command_line' (Chuẩn ECS)")
            print(f"    -> Giá trị mẫu: {cmd_line_ecs}")
            
        else:
            print("[!] CẢNH BÁO ĐỎ: Tìm thấy log Event ID 1 nhưng KHÔNG THẤY trường CommandLine nào cả.")
            print("    -> Dưới đây là cấu trúc JSON thực tế của log này, hãy kiểm tra xem Command Line đang nằm ở đâu:")
            print("-" * 50)
            print(json.dumps(latest_log, indent=2))
            print("-" * 50)

    except Exception as e:
        print(f"[!] Lỗi khi query log: {e}")

if __name__ == "__main__":
    main()