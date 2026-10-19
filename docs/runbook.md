# Runbook: dựng, vận hành, mô phỏng, hủy

## 0. Yêu cầu
AWS account lab (một người dùng), Terraform ≥ 1.10, AWS CLI, Python 3.12, một GitHub repo, một Slack workspace thử nghiệm.

## 1. Bootstrap (một lần, chạy local với quyền admin)
```bash
cd infra/bootstrap
terraform init && terraform apply -var github_repo=<user>/SIEM-SOAR-LAB
terraform output github_variables
```
Trong GitHub → Settings:
* **Variables** (repository): `TFSTATE_BUCKET, PLAN_ROLE_ARN, APPLY_ROLE_ARN, RULES_ROLE_ARN`, tùy chọn `AWS_REGION` (mặc định `us-east-1`); **secret** `ALERT_EMAIL` (log Actions của repo public ai cũng xem được); tùy chọn `SLACK_CHANNEL`, `DRY_RUN` (mặc định `true`), `ENABLE_FAULT_INJECTION` (mặc định `false`).
* **Environments**: `lab` và `lab-rules`, bật *Required reviewers* (đây là chốt phê duyệt trước khi apply/deploy).
* Local: `cp infra/envs/lab/backend.hcl.example infra/envs/lab/backend.hcl` và sửa tên bucket.

## 2. Triển khai mặt phẳng always-on
Merge vào `main` → workflow **terraform** (apply cần reviewer). Hoặc local:
```bash
cd infra/envs/lab
terraform init -backend-config=backend.hcl
terraform apply -var alert_email=you@example.com        # dry_run = true theo mặc định
```
Xác nhận email đăng ký SNS. `terraform output core` cho tên bucket/bảng/URL Slack.

## 3. Slack
1. api.slack.com/apps → *Create New App* → From scratch.
2. **OAuth & Permissions** → Bot scope `chat:write` (+ `chat:write.public` nếu kênh công khai) → Install → copy *Bot User OAuth Token*.
3. **Socket Mode** → **tắt** (khi bật, Slack gửi nút bấm qua WebSocket và ẩn ô Request URL; hệ thống này nhận nút bấm qua
   HTTPS có kiểm chữ ký). Rồi **Interactivity & Shortcuts** → bật, *Request URL* = kết quả của
   `terraform output -json core | jq -r .slack_interaction_url` → *Save Changes*.
4. **Basic Information** → copy *Signing Secret*. Lấy *Member ID* của người duyệt (Profile → ⋮ → Copy member ID) và *Channel ID*.
5. Đặt secret **ngoài Terraform**:
```bash
aws ssm put-parameter --overwrite --type SecureString --name /siemsoar/slack/bot_token      --value xoxb-...
aws ssm put-parameter --overwrite --type SecureString --name /siemsoar/slack/signing_secret --value ...
aws ssm put-parameter --overwrite --type String       --name /siemsoar/slack/approver_ids   --value U012ABC,U034DEF
aws ssm put-parameter --overwrite --type String       --name /siemsoar/slack/channel        --value C0123456
```
Slack chưa cấu hình → hệ thống vẫn chạy: thông báo qua SNS và quyết định bằng `soarctl` (xem mục 7).

## 4. Phiên làm việc (mặt phẳng on-demand)
Actions → **lab-session** → `up` (ví dụ 4 giờ). Workflow tạo VPC/Wazuh/EC2 lab và bật timer tự tắt.
Lần đầu Wazuh cần ~10–15 phút (xem `/var/log/siemsoar-userdata.log` qua SSM Session Manager).
```bash
terraform -chdir=infra/envs/lab output lab                 # có lệnh port-forward dashboard
aws ssm get-parameter --name /siemsoar/wazuh/admin_password --with-decryption --query Parameter.Value --output text
python -m tools.soarctl lab status | extend --hours 2 | down
```
Kết thúc phiên: `python -m tools.soarctl lab down` (stop máy, hủy timer; dữ liệu Wazuh giữ nguyên) — hoặc timer tự stop.
`lab-session → down` **hủy hẳn** mặt phẳng lab (manager và dữ liệu Wazuh): chỉ dùng khi kết thúc đồ án.
Sau khi đổi `agent/` (cấu hình FIM, auditd): merge → `terraform` apply (đưa file lên bucket bootstrap) →
`python -m tools.labctl refresh-agents` (áp lên sensor và máy mục tiêu đang chạy).

## 5. Chạy lần đầu an toàn (checklist)
Mọi rule vào repo ở **shadow** (đề cương 5.3: rule mới chỉ ghi nhận alert, không tạo case). Vì vậy phiên đầu là phiên **đo**:
1. `dry_run=true` (mặc định). `python -m simulation.runner run-all --kind atomic --kind ssm_shell` → các test Atomic và
   kịch bản lành tính chạy trên máy lab; runner đọc alert SIEM của từng lượt. Chưa có case Wazuh (rule đang shadow).
2. `python -m simulation.runner run aws-guardduty-sample` → case từ GuardDuty (tài nguyên mẫu không tồn tại → chỉ cần
   Acknowledge): kiểm đường EventBridge → case → Slack/email.
3. `python -m evaluation.evaluate` → bảng **tầng phát hiện**: TP/FN của từng rule shadow và FP đo được từ kịch bản lành tính.
4. **Promote bằng PR riêng** (kịch bản vòng đời rule): `python -m tools.rulesctl promote wazuh-100110 active` (lệnh tự cập
   nhật cờ `case` trong các kịch bản), mở PR kèm số liệu bước 3, merge → **rules-deploy**.
5. `python -m simulation.runner run host-useradd` (vẫn `dry_run=true`) → case, Slack gửi thẻ, **Approve** → workflow đi hết,
   SG **chưa** đổi.
6. Đặt `DRY_RUN=false` → apply → lặp lại: SG cô lập thật (máy vẫn gửi log về Wazuh qua cổng 1514), snapshot thật, restore
   xác minh thật.
7. Robustness (`robust-*`, cần rule đã active và `ENABLE_FAULT_INJECTION=true` ở lần apply đó, rồi tắt lại).
8. Rollback để minh họa: `git revert` PR promote → merge → rule về shadow.

Trước khi chạy `aws-stratus-cloudtrail-stop`, đặt `SIEMSOAR_LAB_ACCOUNT_ID` thành account ID lab đã được duyệt và xác nhận AWS credentials hiện tại trỏ đúng account (cần binary `stratus`). Runner từ chối account không khớp. Trình tự: `stratus warmup` bằng credential của người vận hành (Stratus tự tạo trail `stratus-red-team-*`), runner xóa key cũ và tạo access key mới cho IAM user vùng simulation (`SIEMSOAR_SIM_USER`, mặc định `lab-victim`, chỉ được `cloudtrail:StopLogging` trên trail của Stratus), `stratus detonate` bằng key đó, rồi `stratus cleanup` bằng credential người vận hành. GuardDuty sinh `Stealth:IAMUser/CloudTrailLoggingDisabled` trỏ tới key của `lab-victim` → case với plan `iam_key_disable`.
GuardDuty cần tới khoảng 18 phút (đo ở phiên 2; AWS không công bố giới hạn trên). Runner chờ tối đa 30 phút và dừng ngay khi case xuất hiện. Đánh giá không cắt theo thời gian: key được tạo riêng cho lượt chạy, nên finding nào nêu key đó đều thuộc lượt ấy, dù đến muộn. Stratus kiểm tra đăng nhập bằng
`ec2:DescribeAccountAttributes` (policy của `lab-victim` cho phép đúng lệnh đọc này). Bước cleanup xóa trail bằng
key người vận hành nên GuardDuty cũng báo một finding cùng loại về key đó. Case ấy **chỉ thông báo** (user ngoài
tiền tố `lab-`), chỉ cần Acknowledge, và không được tính vào lượt chạy.

Kịch bản nhiều máy (`xhost-*`, `target-useradd`): chạy từ sensor nhắm vào `lab-target-1` (`{target_ip}`), `observe_on`
chỉ máy nhận phát hiện. Runner **từ chối** chạy trên máy còn tag `siemsoar:isolated-case`: quyết định/khôi phục case đó
trước, nếu không alert mới sẽ chặn restore (đúng thiết kế). Chạy kịch bản từ một bản checkout cố định (ví dụ
`git worktree add ../run-main origin/main`), không từ thư mục đang sửa code: runner đọc lại thư mục kịch bản mỗi lượt.

Pcap cho test Suricata được bắt lại bằng `python -m tools.capture_pcaps` (cần Docker; chạy thủ tục Atomic trong mạng Docker tạm, ghi `rules/pcaps/provenance.json`). Khi thêm rule ET Open: tạo metadata `source: et-open` + `wazuh_rule_id`, rồi `python -m tools.refdata et-open` để ghim nội dung rule.

## 6. Vận hành rule
Xem [detection-as-code.md](detection-as-code.md). Nhanh: sửa/thêm rule → PR (CI) → merge → **rules-deploy** → shadow →
quan sát FP → PR promote → active. Rollback: `git revert` + merge, hoặc chạy `rules-deploy` với `rollback_sha`.

## 7. Kênh dự phòng khi Slack không dùng được
```bash
python -m tools.soarctl list --status NOTIFIED
python -m tools.soarctl show <case_id>
python -m tools.soarctl decide <case_id> --gate approval --decision approve|dismiss|acknowledge --approver <Slack member ID>
python -m tools.soarctl decide <case_id> --gate restore  --decision restore_tp|restore_fp --approver <Slack member ID>
```
Cùng một đường kiểm tra với Slack (trạng thái, token một lần, audit `channel=cli`). Đây là cổng **của con người**:
`--approver` phải nằm trong `/siemsoar/slack/approver_ids` (cùng danh sách Slack dùng), lệnh chỉ chạy trong terminal
tương tác và yêu cầu gõ lại mã case; credential AWS một mình (script, tự động hóa, trợ lý AI) không phải là phê duyệt.
Audit ghi cả người duyệt (`cli:<member id>`) lẫn danh tính AWS đã chạy lệnh. Thẻ Slack của case được đóng lại dù quyết
định đến từ kênh nào.

## 8. Khi có sự cố
| Triệu chứng | Làm gì |
|---|---|
| Email "workflow failed" / alarm `workflow-failed` | `soarctl show <case>`: xem `failure_error`, `safe_state`, audit (`restore_blocked.reasons`). Tài nguyên giữ nguyên trạng thái an toàn. Khi đã hiểu nguyên nhân: `soarctl recover <case> --approver <member id> --reason "…"` (cổng người như `decide`; kiểm hash `pre_action_state`, trả SG mọi ENI, gỡ thu hồi phiên role, xác minh, ghi audit `manual_recovery`). Case IAM: xem key trong IAM Console |
| Runner báo "contained by case …" | Máy đang bị cô lập: quyết định/khôi phục case đó trước. Không chạy kịch bản trên máy bị cô lập (alert mới sẽ chặn restore, đúng thiết kế) |
| Circuit breaker mở (`BreakerOpen`) | Có >N lần cách ly/giờ: nghi ngờ rule quá nhiễu. Demote rule về shadow, xử lý thủ công |
| Alarm DLQ không rỗng | Alert tới EventBridge nhưng ingest lỗi: xem `siemsoar-ingest-dlq`, sửa, replay |
| Lab quên tắt | Timer sẽ stop; vẫn nên `soarctl lab down` |
| Máy lab vẫn chạy sau giờ tắt | Máy được tạo sau khi hẹn timer: `labctl ensure-timer` (workflow `terraform` tự chạy sau mỗi apply) |
| Restore bị chặn (`restore_blocked`) | Đọc `reasons` trong audit: alert mới sau cách ly, drift SG, hash evidence sai |

## 9. Kết thúc đồ án (tuần 12)
```bash
python -m evaluation.evaluate                    # reports/<ts>/metrics.{json,md}
python -m tools.export_evidence                  # cases+audit+evidence+releases + MANIFEST.json (sha256)
# Actions → lab-session → down, rồi:
terraform -chdir=infra/envs/lab destroy          # evidence bucket có force_destroy
terraform -chdir=infra/bootstrap destroy         # cuối cùng
```
