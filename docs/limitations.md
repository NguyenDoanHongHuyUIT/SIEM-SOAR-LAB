# Giới hạn (6.5) và rủi ro đã biết

**Của đề tài (theo đề cương)**
* Kết quả chỉ áp dụng cho lab nhỏ, lưu lượng mô phỏng có kiểm soát, **một** tài khoản AWS; không đại diện production.
* Telemetry host là loại nhẹ (HIDS/XDR-style), không thay EDR thương mại. Suricata là IDS; chế độ `enforce` chỉ minh họa.
* Độ trễ phân phối log/finding phụ thuộc dịch vụ AWS (GuardDuty và CloudTrail trễ từ vài phút đến hơn chục phút; cần đo thực tế, xem chỉ số detection latency).
* Security Group là **stateful**: đổi SG không cắt ngay kết nối đã tồn tại. Cách ly vẫn chặn kết nối mới; muốn cắt tức thì cần stop instance (khi `risk ≥ stop_risk_threshold`) hoặc NACL.
* Máy bị cách ly (SG `siemsoar-isolation`, do Terraform tạo) chỉ còn **một đường ra**: Wazuh agent → manager TCP 1514, để SIEM vẫn quan sát được máy trong lúc cách ly. Không có đường vào, không SSM, không internet: lệnh dọn dẹp qua SSM chỉ chạy được sau khi restore.
* Khi mặt phẳng on-demand tắt: telemetry host và Suricata có khoảng trống; log AWS trong S3 đọc bù được nhưng không thay giám sát thời gian thực.
* Chưa có kiểm soát cấp Organization (SCP, delegated admin); tách vùng chỉ bằng role/tag/permission boundary/IaC.

**Của hiện thực**
* Role `apply` của GitHub dùng `AdministratorAccess` (đơn giản cho lab) – nên thu hẹp dần; role plan chỉ đọc, role rules least-privilege.
* *Revoke session* cho **instance role** dùng chính sách `AWSRevokeOlderSessions` (từ chối token cấp trước thời điểm cách ly): kẻ tấn công vẫn có thể lấy credential mới từ IMDS nếu chạy trên máy đó; vì vậy cách ly mạng + (tùy rủi ro) stop mới là biện pháp chính.
* Test rule Wazuh vẫn dùng dòng log mẫu và sự kiện FIM tiêm vào analysisd (giống test của chính Wazuh); test Suricata dùng pcap **bắt từ công cụ thật** (thủ tục Atomic nmap/curl trong Docker, `tools/capture_pcaps.py`), không phải traffic production. Đây là unit test của rule; chất lượng phát hiện chỉ lấy từ các lượt chạy trên lab. Wazuh đếm `frequency/timeframe` theo thời điểm nhận sự kiện nên ca “các sự kiện cách nhau quá timeframe” không replay được qua logtest.
* Đã chạy trên AWS thật: 3 phiên lab (17–19/10/2026, một tài khoản, us-east-1). Mọi kịch bản Atomic/lành tính được quan sát qua Wazuh agent thật. T1098.004 #1 (chỉ đổi mtime `authorized_keys`) được rule 100104 phát hiện qua FIM, `host-ssh-burst-existing` được 100120 phát hiện. Số lượt mỗi kịch bản còn nhỏ (1–5), nên precision/recall là **quan sát trên lab**, chưa phải ước lượng thống kê có khoảng tin cậy.
* Các lỗi chỉ lộ ra trên AWS thật đã được sửa và ghi trong lịch sử PR: GuardDuty Low bị lọc, OIDC sub, FIM theo file chết sau rename, quyền SSM, Stratus cần `ec2:DescribeAccountAttributes`, case GuardDuty về key của người vận hành (giờ chỉ thông báo).
* Độ trễ GuardDuty đo được cho `CloudTrailLoggingDisabled`: 18 / 14,6 / 18,6 phút (3 lần). AWS không công bố giới hạn trên. Kịch bản Stratus vì vậy không cắt theo thời gian (key riêng của lượt).
* Cửa sổ chờ (`settle_seconds`) của kịch bản là lựa chọn của người vận hành. Báo cáo kiểm nó bằng số đo (`window_headroom`: phát hiện muộn nhất so với cửa sổ) và đánh dấu "SÁT" khi phát hiện dùng quá nửa cửa sổ.
* **Baseline (cách ly thủ công) chưa đo**: cần các buổi diễn tập người thật cách ly bằng Console. Báo cáo ghi "chưa đo", không điền số.
* Rule 100110 (bọc rule chính thức 5902 "new user") cũng bắn khi admin tạo tài khoản dịch vụ hợp lệ (kịch bản lành tính): đó là FP đo được, rule không phân biệt được ý đồ. Vì vậy mọi case vẫn chờ người duyệt.
* Rule ET Open quản lý được ghim nội dung theo bản phát hành ET (`et-open-managed.json`); phần còn lại của ET Open trên sensor vẫn cập nhật theo `suricata-update` (chỉ là alert tham khảo, không mở case). Sensor đặt `EXTERNAL_NET = any` để thấy traffic giữa các máy lab, làm tăng số alert ET tham khảo.
* Wazuh (cJSON) đọc số JSON thành double: `flow_id` của Suricata > 2^53 tới SOAR đã bị làm tròn, nên được giữ dạng chuỗi và không dùng để đối chiếu chính xác với EVE gốc.
* Ánh xạ GuardDuty→ATT&CK lấy từ MITRE CTID (phát hành 12/2024, ATT&CK 16.1), tên finding đã đối chiếu với danh mục AWS (đổi tên theo lịch sử tài liệu AWS), id kỹ thuật đổi sang v20 theo `revoked-by`. CTID liệt kê finding nào *có thể chỉ ra* kỹ thuật nào, nên một finding S3 có thể mang nhiều kỹ thuật; 141 loại finding đang active chưa có trong CTID nên không có kỹ thuật cho tới khi CTID cập nhật và chạy lại `tools.refdata guardduty`.
* Còn là phán đoán của người vận hành, vì không có nguồn công bố: trọng số `[risk]`, ngưỡng `[severity]` (`basis = "analyst"`) và `level` Wazuh của từng rule. Chúng chỉ dùng để xếp thứ tự xử lý; điều chỉnh bằng số liệu FP đo được (`detection_quality`, `rulesctl tune`).
* Cách ly EC2 xử lý mọi ENI, nhưng quyền `ec2:ModifyNetworkInterfaceAttribute` trên ENI phụ không thể giới hạn theo tag `zone` của instance (AWS không cung cấp điều kiện đó cho network-interface); vùng `workload` được ép ở bước preflight chứ không phải ở IAM cho ENI phụ.
* Case dedup theo (nguồn, rule, tài nguyên[, src_ip]) trong cửa sổ 1 giờ; alert khác ngữ cảnh nhưng cùng khóa sẽ gộp.
* GuardDuty sample finding trỏ tài nguyên không tồn tại → hệ thống hạ xuống `none` và chỉ yêu cầu Acknowledge (có chủ đích, tránh hành động nhầm).
* Wazuh bootstrap dùng `wazuh-install.sh -a`; cần theo dõi thay đổi giữa các phiên bản Wazuh (biến `wazuh_version`).
* Slack yêu cầu phản hồi < 3 giây: Lambda callback chỉ làm việc nhẹ (ghi điều kiện + `SendTaskSuccess`); khởi động lạnh có thể gây Slack hiển thị cảnh báo timeout dù quyết định vẫn được ghi.
* Test tự động dùng moto, không kiểm được ràng buộc IAM/SG thật. Phần đó được kiểm trên lab (cách ly EC2 và vô hiệu key IAM thật, `DRY_RUN=false`). Một môi trường mới vẫn nên chạy phiên đầu với `dry_run=true` (xem runbook).

**Hướng phát triển (6.6)**: multi-account + chính sách tổ chức, thêm cloud khác, endpoint telemetry sâu hơn, tự sinh test từ metadata ATT&CK,
phát hiện rule drift, đánh giá trên traffic thật có kiểm soát, AWS Network Firewall trong phiên ngắn, Security Lake.
