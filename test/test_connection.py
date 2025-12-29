import urllib3
import json
from opensearchpy import OpenSearch

# Tắt cảnh báo certificate
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- CẤU HÌNH (Phải khớp với file siem_client.py) ---
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
        
        # 2. Kiểm tra kết nối cơ bản (Ping/Info)
        if not client.ping():
            print("[!] Lỗi: Không thể ping tới server. Kiểm tra lại IP/Port/Network.")
            return

        info = client.info()
        print(f"[+] Kết nối thành công! Server: {info['version']['distribution']} {info['version']['number']}")
        
    except Exception as e:
        print(f"[!] Lỗi kết nối nghiêm trọng: {e}")
        return

    # 3. Kiểm tra Index
    print(f"\n[*] Đang kiểm tra index '{INDEX_PATTERN}'...")
    if not client.indices.exists(index=INDEX_PATTERN):
        print(f"[!] Cảnh báo: Index '{INDEX_PATTERN}' không tồn tại. Winlogbeat chưa đẩy log về hoặc sai tên index.")
        # Liệt kê các index đang có để debug
        indices = client.cat.indices(format="json")
        print("   -> Các index hiện có:", [i['index'] for i in indices])
        return
    else:
        print(f"[+] Index '{INDEX_PATTERN}' tồn tại.")

    # 4. Lấy thử log mới nhất để kiểm tra cấu trúc (Mapping)
    print(f"\n[*] Đang lấy log mới nhất từ '{INDEX_PATTERN}'...")
    query = {
        "size": 1,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"match_all": {}}
    }

    try:
        response = client.search(body=query, index=INDEX_PATTERN)
        hits = response['hits']['hits']

        if len(hits) == 0:
            print("[!] Index trống rỗng (0 documents). Chưa có log nào được đẩy lên.")
            return

        latest_log = hits[0]['_source']
        print(f"[+] Lấy được log mới nhất lúc: {latest_log.get('@timestamp', 'N/A')}")

        # 5. Kiểm tra trường quan trọng: process.command_line
        # Fuzzer của bạn dựa vào trường này. Nếu log dùng tên khác, Fuzzer sẽ fail.
        print("\n[*] Kiểm tra trường dữ liệu (Field Mapping)...")
        
        # Kiểm tra theo chuẩn ECS
        cmd_line_ecs = latest_log.get('process', {}).get('command_line')
        # Kiểm tra theo chuẩn Raw Windows/Sysmon
        cmd_line_win = latest_log.get('winlog', {}).get('event_data', {}).get('CommandLine')

        if cmd_line_ecs:
            print(f"[+] OK: Tìm thấy trường 'process.command_line'.")
            print(f"   -> Giá trị mẫu: {cmd_line_ecs}")
        elif cmd_line_win:
            print(f"[!] CẢNH BÁO: Không thấy 'process.command_line' nhưng thấy 'winlog.event_data.CommandLine'.")
            print(f"   -> Bạn cần sửa file 'siem_client.py' dòng 'match_phrase' thành 'winlog.event_data.CommandLine'.")
        else:
            print("[!] NGUY HIỂM: Không tìm thấy trường chứa Command Line trong log mới nhất.")
            print("   -> Hãy kiểm tra cấu hình Sysmon/Winlogbeat.")
            # In ra các key tầng 1 để debug
            print("   -> Cấu trúc log hiện tại (keys):", list(latest_log.keys()))

    except Exception as e:
        print(f"[!] Lỗi khi query log: {e}")

if __name__ == "__main__":
    main()