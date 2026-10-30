# Đánh giá (Chương 6)

Quy trình: chạy kịch bản lặp lại → mỗi lượt có `run_id`, **máy mục tiêu**, kỹ thuật, độc hại/lành tính và kỳ vọng (ground truth)
lưu ở `RUN#<id>` → runner đọc **mọi alert SIEMSOAR** Wazuh sinh trên máy mục tiêu trong cửa sổ chạy (`run.siem_alerts`, mọi trạng thái
vòng đời) → `evaluate` ghép case với lượt chạy (theo `run_id` nếu log mang được nó, nếu không theo **máy mục tiêu + cửa sổ thời gian**;
hai lượt chồng lấn trên cùng máy thì case bị coi là mơ hồ, không gán) → xuất `reports/<ts>/metrics.{json,md}`.

```bash
python -m simulation.runner run-all --repeat 5         # lặp để có phân bố
python -m evaluation.evaluate --days 30      # giờ lab, chi phí, baseline lấy từ CloudTrail/GuardDuty/Cost Explorer/Pricing API
```

## Chỉ số ↔ hiện thực (Bảng 4)
| Chỉ số | Cách tính | Nguồn dữ liệu |
|---|---|---|
| Detection latency per source | `case.created_at − alert.event_time` (đường ống) và `case.created_at − run.started_at` (đầu cuối), p50/p95 theo nguồn | case + run |
| Time to containment | `ISOLATED − APPROVED` (đã xác minh bằng API) | `containment_seconds` |
| Time to evidence preservation | `pre_action_state ghi xong − APPROVED` | `evidence_seconds` |
| TP/FP theo rule (**hai tầng**) | *Tầng phát hiện* (`detection_quality`, alert SIEM, kể cả rule shadow): TP = rule kỳ vọng có alert trong lượt độc hại, FN = không có, FP = mọi alert trong lượt lành tính (kể cả FP đã khai báo `false_positive: true`), **trừ** alert của rule ngoại lệ mà kịch bản lành tính khai báo là kết quả đúng (100112, 100146): báo cáo ghi riêng số lượt chúng nhận hoạt động lành tính, không tính TP/FP, "ngoài dự kiến" = alert không được dự đoán trong lượt độc hại. *Tầng case* (`rule_quality`): TP/FP như trên cho case; **vi phạm shadow** = case từ rule shadow; FN tách `fn_detection` (rule không bắn) / `fn_pipeline` (bắn nhưng không thành case) / `fn_unverified`; FP do người dismiss chỉ tính khi người dismiss **không** phải `sim:ground-truth` | ground truth + `run.siem_alerts` |
| Cơ hội FP của rule | một lượt lành tính chỉ là cơ hội bắn nhầm của rule R khi R **có trong bản rule đang deploy** lúc đó (`run.rules_release`, tra trong lịch sử git; lượt cũ chưa ghi bản rule thì so ngày `created`). Rule chưa có lượt lành tính nào: precision ghi *chưa đo*, không ghi 1.0 | run + git |
| Khoảng tin cậy | mọi precision/recall kèm khoảng **Clopper–Pearson 95%** (chính xác, từ phân phối nhị thức): 5/5 chỉ chứng minh tỉ lệ ≥ 0,478 | `clopper_pearson` |
| Độ phủ thủ tục công khai | theo kỹ thuật: số test trong chỉ mục Atomic Red Team Linux đã ghim / số test đã chạy / số test được phát hiện; test chạy ở chế độ quan sát tính là đã chạy, chưa phát hiện | chỉ mục ART + kịch bản + run |
| ATT&CK coverage | kỹ thuật phát hiện đúng / kỹ thuật đã mô phỏng **bằng thủ tục công khai** (Atomic/Stratus/pcap Atomic); kỹ thuật do thủ tục lab tự khai báo liệt kê riêng, không tính vào tỉ lệ | metadata + run |
| Alert duplication reduction | `1 − cases / Σ alert_count` | case |
| Rule deployment lead time | `deployed_at − commit_time` | `releases/*/deployment.json` |
| Robustness under failure | pass-rate của `robust-*` (double click, lỗi giữa chừng, Slack tắt) + kiểm chứng từng bước | run |
| Case FAILED | từng case kèm lỗi (`failure_error`), nguồn gốc (lỗi robustness cố ý tiêm / lỗi vận hành thật), trạng thái an toàn được giữ và thời điểm khôi phục tay; không in tài nguyên (ID tài nguyên IAM chứa ID access key) | case |
| Operating cost per session | **thực tế** từ Cost Explorer theo tag `Project=siem-soar-lab` (cần kích hoạt tag trong Billing, dữ liệu trễ ~24 h) và **ước tính** compute từ giá niêm yết của Pricing API × giờ lab đọc từ CloudTrail (RunInstances/StartInstances/StopInstances, gồm cả lần dừng do timer) | CloudTrail, Cost Explorer, Pricing API |

## Kịch bản: thủ tục công khai, kỹ thuật không gõ tay
| Kịch bản | Thủ tục (nguồn) | Kỹ thuật (suy ra từ) | Rule kỳ vọng |
|---|---|---|---|
| `host-useradd` | Atomic T1136.001 #1 (`useradd -r`) | chỉ mục ART | 100110, 100100 (active), 100102 (shadow) |
| `host-root-group-user` | Atomic T1136.001 #6 (`useradd -g 0` + `chpasswd`) | chỉ mục ART | 100110, 100100, 100102 |
| `host-reactivate-account` | Atomic T1078.003 #9 (lock/expire/unlock) | chỉ mục ART | 100102 (100110/100100 là tác dụng phụ, `optional`) |
| `host-sudoers` | Atomic T1548.003 #5 (`Defaults !tty_tickets`) | chỉ mục ART | 100103 |
| `host-ssh-authkeys` | Atomic T1098.004 #1 | chỉ mục ART | 100104 |
| `host-ssh-credstuffing` | Atomic T1110.004 #1 (482 cặp user:pass của ART) | chỉ mục ART | 100121 |
| `net-portscan` | Atomic T1046 #2 (`nmap -sS` tới manager) | chỉ mục ART | ET 2009582 → 110101 |
| `net-malicious-ua` | Atomic T1071.001 #3 (user-agent mã độc) | chỉ mục ART | ET 2009525 → 110102 |
| `aws-stratus-cloudtrail-stop` | Stratus `aws.defense-evasion.cloudtrail-stop`, kích nổ bằng key của `lab-victim` | finding Stratus ghi trong tài liệu → CTID | `Stealth:IAMUser/CloudTrailLoggingDisabled` (case, `iam_key_disable`) |
| `host-benign-service-account` | quản trị tạo service account (lành tính) | — | ngoại lệ 100112 (100110 không được bắn); FP đã biết: 100100, 100102 |
| `net-benign-admin` | curl metadata service, trang công khai, `apt-get update` | — | FP đã biết: ET HUNTING 2034567 → 110103 |
| `host-canary-shadow` | chạm thư mục canary (lành tính) | — | 100101 (kiểm vòng đời shadow) |
| `host-benign-custom-service` | tạo service tùy chỉnh trong `/etc/systemd/system`, `daemon-reload`, chạy, gỡ | — | FP đo được (20/10/2026) và đã khai báo: 100141 (file unit do shell ghi, như Atomic) |
| `host-benign-file-housekeeping` | `chmod` thông thường, thư mục sticky (1777) và **setgid dùng chung (2775)**, `truncate`/`rm` log | — | FP đo được và đã khai báo: 100144 (`chmod 2775` trên thư mục); 100143 không bắn |
| `host-benign-admin-maintenance` | cài/gỡ gói `sysstat` (gói Ubuntu có `/etc/cron.d/sysstat`), thêm `HISTTIMEFORMAT` vào `/etc/profile.d` | — | ngoại lệ who-data **100146** (cron do `dpkg` dưới `apt-get` ghi; 100140 không được bắn); FP đã khai báo: 100142 (`profile.d`), 100145 (perl của debconf, `optional`) |
| `host-ssh-burst-existing` | thủ tục lab (sshd phụ có mật khẩu) | **tự khai**, không làm bằng chứng | 100120 |
| `xhost-portscan-target` | Atomic T1046 #2 từ sensor tới `lab-target-1` | chỉ mục ART | ET 2009582 → 110101 (trên sensor) |
| `xhost-ssh-credstuffing-target` | Atomic T1110.004 #1 từ sensor tới `lab-target-1` (`observe_on: lab-target`) | chỉ mục ART | 100121 (trên máy mục tiêu) |
| `target-useradd` | Atomic T1136.001 #1 chạy trên `lab-target-1` | chỉ mục ART | 100110 (case, cô lập máy mục tiêu) |
| 13 kịch bản `host-cron-*`, `host-systemd-service`, `host-bashrc`, `host-system-profile`, `host-history-*`, `host-read-*`, `host-enum-*`, `host-set{u,g}id` | Atomic T1053.003 #3/#4, T1543.002 #1, T1546.004 #2/#4, T1070.003 #1/#5, T1003.008 #1/#3, T1087.001 #1/#3, T1548.001 #3/#5 | chỉ mục ART | rule shadow viết từ sự kiện quan sát trên lab: 100140 (cron), 100141 (systemd), 100142 (shell start-up), 100143 (xóa/rỗng lịch sử), 100144 (SetUID/SetGID), 100145 (đọc `/etc/shadow`); `host-read-passwd`, `host-enum-*`: **không có tín hiệu phân biệt**, giữ `expect: []` |
| `host-audit-disable`, `host-audit-delete-rules` | Atomic T1685.004 #2 (`auditctl -e 0`), #1 (`auditctl -D`) | chỉ mục ART | #2 → **100147** (shadow, viết từ bản ghi `op=set audit_enabled=0` của lượt quan sát 30/10/2026); #1: **không có tín hiệu phân biệt** (giống `augenrules --load` lành tính); có thể làm syscheckd crash (wazuh/wazuh#40844) → **100148** khai báo `optional`. Cleanup nạp lại rule khi agent đã dừng (wazuh/wazuh#40844) |
| `host-health-fim-crash` | thủ tục lab: một tiến trình `sleep` và `wazuh-syscheckd` nhận SIGSEGV (sự cố của wazuh/wazuh#40844, tạo có chủ đích) | **tự khai**, không làm bằng chứng | 100148 (rule sức khỏe, shadow); `sleep` không được làm 100148 bắn |

* `scripts/run_atomic.py` tự thực thi YAML Atomic theo đúng quy ước ART (thay `#{input}`, `PathToAtomicsFolder`, executor của test, kiểm `prereq_command`, tải file `src/` cùng commit). Thiếu điều kiện tiên quyết → mã 3 → *lỗi thực thi*, không phải FN. Mã thoát của lệnh atomic được ghi lại; hành vi có xảy ra hay không do `verify:` của kịch bản quyết định. Đã chạy thật trên Ubuntu 24.04 cho T1136.001 #1/#6, T1078.003 #9, T1548.003 #5, T1098.004 #1, T1110.004 #1 (thiếu sshpass → mã 3).
* `simulation/catalog.py` kiểm từng kịch bản với nguồn ghim: GUID phải thuộc đúng kỹ thuật trong chỉ mục ART (cùng commit), finding của Stratus phải đúng finding mà trang Stratus ghi và là loại *active* trong danh mục AWS, pcap phải có trong `rules/pcaps/provenance.json`. Kỳ vọng phải trỏ tới rule có thật, khớp trạng thái vòng đời, và kỹ thuật của kịch bản phải liên quan tới nhãn ATT&CK của rule (nếu không, lint báo "mapping hoặc kỳ vọng sai").
* Sau lượt **lành tính**, runner đóng case sinh ra trên máy mục tiêu với actor `sim:ground-truth` (để không chặn restore về sau); bộ đánh giá không bao giờ tính chúng là phản hồi của người.
* Không còn rule khớp marker do chính kịch bản ghi (`100130` đã bị xóa). Cơ chế `canary: true` của bộ đánh giá vẫn có cho trường hợp ai đó thêm rule như vậy: nó chỉ được báo riêng, không tính TP/FP/FN hay ATT&CK coverage. Tính sống của pipeline được kiểm bằng GuardDuty sample finding của AWS (`aws-guardduty-sample`, `pipeline_only`).
* **Kịch bản shadow phải chứng minh rule đã bắn.** `case: false` một mình sẽ PASS cả khi rule hỏng. Runner hỏi manager (`alerts.json`, qua SSM) và ghi `run.observed`; `evaluate` chỉ tính `shadow_ok` khi alert thật sự có, `shadow_missed` (và FN nếu kịch bản độc hại) khi không, `shadow_unverified` khi chưa ai kiểm.
* **Lượt chạy lỗi thực thi** (SSM/atomic/Stratus lỗi, lệnh `verify:` thất bại) mang `execution_error` và bị loại khỏi FN, coverage; **case từ GuardDuty sample** (`sample: true`) bị loại khỏi TP/FP và độ trễ.

## Baseline (6.3)
Baseline = GuardDuty gửi email mặc định + người tự cách ly bằng AWS Console. **Đo, không giả định, không bấm giờ tay**: `evaluation/sources.py` lấy các GuardDuty finding thật (loại sample), tìm lệnh cách ly đầu tiên của một **người** (CloudTrail: `ModifyInstanceAttribute`, `StopInstances`, `UpdateAccessKey` … bởi principal không phải role của SOAR) trên đúng tài nguyên trong 6 giờ sau finding, và đếm các lệnh thay đổi trạng thái (`readOnly=false`) của người đó trong khoảng đó = số thao tác thủ công. Chỉ tính lệnh gọi từ **Console** (CloudTrail `sessionCredentialFromConsole = "true"`, [tài liệu AWS](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html)). Lệnh của script cùng credential, ví dụ runner xóa key cũ của `lab-victim` trước mỗi lượt Stratus, không phải người phản ứng với cảnh báo. Cần các buổi diễn tập người thật cách ly bằng Console, lặp ≥ 5 lần: chạy `aws-stratus-cloudtrail-stop`, **không** bấm thẻ Slack, khi có cảnh báo thì vô hiệu key trong IAM Console. Không có đường nhập số bấm giờ tay.
`evaluate` so **cùng một khoảng**: từ lúc phát hiện sẵn sàng (baseline: finding được tạo; SOAR: case được tạo từ finding) đến khi ngăn chặn xong. Cả hai đều gồm thời gian người phản ứng. `containment_seconds` (từ lúc duyệt) chỉ là bước tự động, không dùng để so. Số thao tác: baseline đếm lệnh Console thay đổi trạng thái; SOAR đếm quyết định trên chính case (`approved_at`, `restoring_at`, …).

## Tiêu chí thành công (6.4) ↔ kiểm tra
| Tiêu chí | Kiểm tra |
|---|---|
| Kịch bản được phát hiện và xử lý end-to-end | `aws-stratus-cloudtrail-stop` (case + vô hiệu key IAM) ngay từ đầu; `host-useradd`, `host-root-group-user` (case + cách ly EC2) sau khi promote 100110/100100 lên active |
| Rule lifecycle shadow/active/rollback | rule shadow (100102-100104, 100120/100121, ET 110101-110103) có alert nhưng không case; promote `rulesctl promote suricata-2009525 active` khi `detection_quality` cho thấy TP mà không FP, rollback bằng `git revert` |
| Phê duyệt chỉ một kết quả hợp lệ | `robust-double-click`; test `test_slack_endpoint_happy_path_and_double_click` |
| Isolation và restore có xác minh | `verify` bằng API; `restore.validate` (hash evidence, drift, alert mới) |
| Lỗi kết thúc ở trạng thái an toàn | `robust-mid-failure`; test fail-safe |
| Audit đủ để đối chiếu | bảng audit mỗi case + `export_evidence` (MANIFEST sha256) |
