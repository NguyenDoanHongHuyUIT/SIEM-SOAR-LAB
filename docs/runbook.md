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
* **Variables** (repository): `TFSTATE_BUCKET, PLAN_ROLE_ARN, APPLY_ROLE_ARN, RULES_ROLE_ARN, ALERT_EMAIL`; tùy chọn `SLACK_CHANNEL`, `DRY_RUN` (mặc định `true`), `ENABLE_FAULT_INJECTION` (mặc định `false`).
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
3. **Interactivity & Shortcuts** → bật, *Request URL* = kết quả của `terraform output -json core | jq -r .slack_interaction_url`.
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
Kết thúc: `lab-session → down` (hủy hẳn) — hoặc timer chỉ *stop* instance nếu bạn quên.

## 5. Chạy lần đầu an toàn (checklist)
1. `dry_run=true` (mặc định). Chạy `python -m simulation.runner run host-marker` → case xuất hiện, Slack gửi thẻ, bấm **Approve** (nếu plan là `none` thì **Acknowledge**).
2. `python -m simulation.runner run aws-guardduty-sample` → case từ GuardDuty (tài nguyên mẫu không tồn tại → chỉ cần Acknowledge).
3. `python -m simulation.runner run host-useradd` với `dry_run=true` → xem workflow đi hết, SG **chưa** đổi.
4. Đặt `DRY_RUN=false` (GitHub variable) → apply → lặp lại: SG cô lập thật, snapshot thật, restore xác minh thật.
5. `python -m simulation.runner run-all` (robustness cần `ENABLE_FAULT_INJECTION=true` ở lần apply đó, rồi tắt lại).

## 6. Vận hành rule
Xem [detection-as-code.md](detection-as-code.md). Nhanh: sửa/thêm rule → PR (CI) → merge → **rules-deploy** → shadow →
quan sát FP → PR promote → active. Rollback: `git revert` + merge, hoặc chạy `rules-deploy` với `rollback_sha`.

## 7. Kênh dự phòng khi Slack không dùng được
```bash
python -m tools.soarctl list --status NOTIFIED
python -m tools.soarctl show <case_id>
python -m tools.soarctl decide <case_id> --gate approval --decision approve|dismiss|acknowledge
python -m tools.soarctl decide <case_id> --gate restore  --decision restore_tp|restore_fp
```
Cùng một đường kiểm tra với Slack (trạng thái, token một lần, audit `channel=cli`).

## 8. Khi có sự cố
| Triệu chứng | Làm gì |
|---|---|
| Email "workflow failed" / alarm `workflow-failed` | `soarctl show <case>`: xem `failure_error`, `safe_state`. Tài nguyên giữ nguyên trạng thái an toàn; khôi phục thủ công theo `s3://…-evidence-…/cases/<case>/pre_action_state.json` |
| Circuit breaker mở (`BreakerOpen`) | Có >N lần cách ly/giờ: nghi ngờ rule quá nhiễu. Demote rule về shadow, xử lý thủ công |
| Alarm DLQ không rỗng | Alert tới EventBridge nhưng ingest lỗi: xem `siemsoar-ingest-dlq`, sửa, replay |
| Lab quên tắt | Timer sẽ stop; vẫn nên `lab-session → down` |
| Restore bị chặn (`restore_blocked`) | Đọc `reasons` trong audit: alert mới sau cách ly, drift SG, hash evidence sai |

## 9. Kết thúc đồ án (tuần 12)
```bash
python -m evaluation.evaluate                    # reports/<ts>/metrics.{json,md}
python -m tools.export_evidence                  # cases+audit+evidence+releases + MANIFEST.json (sha256)
# Actions → lab-session → down, rồi:
terraform -chdir=infra/envs/lab destroy          # evidence bucket có force_destroy
terraform -chdir=infra/bootstrap destroy         # cuối cùng
```
