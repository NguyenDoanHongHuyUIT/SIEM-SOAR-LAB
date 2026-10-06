# Giới hạn (6.5) và rủi ro đã biết

**Của đề tài (theo đề cương)**
* Kết quả chỉ áp dụng cho lab nhỏ, lưu lượng mô phỏng có kiểm soát, **một** tài khoản AWS; không đại diện production.
* Telemetry host là loại nhẹ (HIDS/XDR-style), không thay EDR thương mại. Suricata là IDS; chế độ `enforce` chỉ minh họa.
* Độ trễ phân phối log/finding phụ thuộc dịch vụ AWS (GuardDuty và CloudTrail trễ từ vài phút đến hơn chục phút; cần đo thực tế, xem chỉ số detection latency).
* Security Group là **stateful**: đổi SG không cắt ngay kết nối đã tồn tại. Cách ly vẫn chặn kết nối mới; muốn cắt tức thì cần stop instance (khi `risk ≥ stop_risk_threshold`) hoặc NACL.
* Khi mặt phẳng on-demand tắt: telemetry host và Suricata có khoảng trống; log AWS trong S3 đọc bù được nhưng không thay giám sát thời gian thực.
* Chưa có kiểm soát cấp Organization (SCP, delegated admin); tách vùng chỉ bằng role/tag/permission boundary/IaC.

**Của hiện thực**
* Role `apply` của GitHub dùng `AdministratorAccess` (đơn giản cho lab) – nên thu hẹp dần; role plan chỉ đọc, role rules least-privilege.
* *Revoke session* cho **instance role** dùng chính sách `AWSRevokeOlderSessions` (từ chối token cấp trước thời điểm cách ly): kẻ tấn công vẫn có thể lấy credential mới từ IMDS nếu chạy trên máy đó; vì vậy cách ly mạng + (tùy rủi ro) stop mới là biện pháp chính.
* Mini-engine kiểm thử rule offline chỉ hỗ trợ tập cú pháp đang dùng; **không** thay `wazuh-logtest`/Wazuh thật. Quy tắc `frequency` được coi là kích hoạt khi đạt ≥ N sự kiện; hành vi chính xác của engine cần xác nhận khi chạy thật.
* Case dedup theo (nguồn, rule, tài nguyên[, src_ip]) trong cửa sổ 1 giờ; alert khác ngữ cảnh nhưng cùng khóa sẽ gộp.
* GuardDuty sample finding trỏ tài nguyên không tồn tại → hệ thống hạ xuống `none` và chỉ yêu cầu Acknowledge (có chủ đích, tránh hành động nhầm).
* Wazuh bootstrap dùng `wazuh-install.sh -a`; cần theo dõi thay đổi giữa các phiên bản Wazuh (biến `wazuh_version`).
* Slack yêu cầu phản hồi < 3 giây: Lambda callback chỉ làm việc nhẹ (ghi điều kiện + `SendTaskSuccess`); khởi động lạnh có thể gây Slack hiển thị cảnh báo timeout dù quyết định vẫn được ghi.
* Test dùng moto: không kiểm tra được các ràng buộc IAM/SG thật. Phiên đầu tiên phải chạy `dry_run=true` (xem runbook).

**Hướng phát triển (6.6)**: multi-account + chính sách tổ chức, thêm cloud khác, endpoint telemetry sâu hơn, tự sinh test từ metadata ATT&CK,
phát hiện rule drift, đánh giá trên traffic thật có kiểm soát, AWS Network Firewall trong phiên ngắn, Security Lake.
