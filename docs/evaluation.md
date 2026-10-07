# Đánh giá (Chương 6)

Quy trình: chạy kịch bản lặp lại → mỗi lượt có `run_id` + kỳ vọng (ground truth) lưu ở `RUN#<id>` → `evaluate` ghép case với lượt chạy
(kịch bản tự viết có `run_id` trong syslog; Atomic Red Team, cloud, network: theo cửa sổ thời gian + rule/finding kỳ vọng) → xuất `reports/<ts>/metrics.{json,md}`.

```bash
python -m simulation.runner run-all --repeat 5         # lặp để có phân bố
python -m evaluation.evaluate --baseline evaluation/baseline.csv --sessions evaluation/sessions.csv
```

## Chỉ số ↔ hiện thực (Bảng 4)
| Chỉ số | Cách tính | Nguồn dữ liệu |
|---|---|---|
| Detection latency per source | `case.created_at − alert.event_time` (đường ống) và `case.created_at − run.started_at` (đầu cuối), p50/p95 theo nguồn | case + run |
| Time to containment | `ISOLATED − APPROVED` (đã xác minh bằng API) | `containment_seconds` |
| Time to evidence preservation | `pre_action_state ghi xong − APPROVED` | `evidence_seconds` |
| TP/FP theo rule | TP: case khớp kỳ vọng của lượt `malicious`; FP: lượt không độc hại, hoặc người dismiss/`restore_fp`; **vi phạm shadow**: case sinh ra từ rule shadow; FN: kỳ vọng có case nhưng không có | ground truth |
| ATT&CK coverage | kỹ thuật phát hiện đúng / kỹ thuật đã mô phỏng; kèm danh sách kỹ thuật trong rule active | metadata + run |
| Alert duplication reduction | `1 − cases / Σ alert_count` | case |
| Rule deployment lead time | `deployed_at − commit_time` | `releases/*/deployment.json` |
| Robustness under failure | pass-rate của `robust-*` (double click, lỗi giữa chừng, Slack tắt) + kiểm chứng từng bước | run |
| Operating cost per session | ước tính từ giá niêm yết × giờ (`sessions.csv`); đối chiếu Cost Explorer theo tag `Project=siem-soar-lab` | sessions.csv |

## Atomic Red Team và rule canary
* `host-useradd` chạy **atomic T1136.001 #1 nguyên bản** của Red Canary (`scripts/run_atomic.py` + `atomic-operator`). `atomic-operator` thoát mã 0 kể cả khi lệnh atomic lỗi, nên kịch bản có `verify:` (lệnh phải thành công), nếu không lượt chạy bị ghi là *lỗi thực thi* thay vì FN giả.
* ART không có atomic Linux tương ứng cho SSH brute force hay FIM `/etc/passwd` trực tiếp, nên `host-ssh-burst` và `host-fim-passwd` vẫn tự viết (ghi rõ trong file).
* Rule `wazuh-100130` khớp **marker do chính kịch bản ghi** (`logger`), nên luôn "đúng". Nó mang `canary: true`: chỉ chứng minh pipeline sống, được báo riêng ở mục *Canary pipeline*, **không** tính TP/FP/FN hay ATT&CK coverage.

## Baseline (6.3)
Baseline = GuardDuty gửi email mặc định + tự cách ly bằng AWS Console. **Đo, không giả định**: dùng `evaluation/baseline.example.csv`
(copy thành `baseline.csv`), bấm giờ từ lúc email tới đến lúc cách ly xong và đếm thao tác thủ công; lặp ≥ 5 lần cho mỗi kịch bản AWS/host.
`evaluate` so: thời gian containment, số thao tác thủ công (SOAR = 2 click), và lưu ý rằng thời gian SOAR tính từ lúc *duyệt* nên so sánh công bằng là
`seconds_to_notice + độ trễ duyệt` với baseline.

## Tiêu chí thành công (6.4) ↔ kiểm tra
| Tiêu chí | Kiểm tra |
|---|---|
| Kịch bản được phát hiện và xử lý end-to-end | `host-*`, `aws-guardduty-sample`, `net-traversal` PASS |
| Rule lifecycle shadow/active/rollback | `host-canary-shadow`, `net-*-shadow` (không case) + demo vòng đời |
| Phê duyệt chỉ một kết quả hợp lệ | `robust-double-click`; test `test_slack_endpoint_happy_path_and_double_click` |
| Isolation và restore có xác minh | `verify` bằng API; `restore.validate` (hash evidence, drift, alert mới) |
| Lỗi kết thúc ở trạng thái an toàn | `robust-mid-failure`; test fail-safe |
| Audit đủ để đối chiếu | bảng audit mỗi case + `export_evidence` (MANIFEST sha256) |
