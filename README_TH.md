# Wazuh แบบ Manual Ground Truth

โค้ดชุดนี้ไม่สร้างและไม่ใช้ `event_action`, `source_system`, `operation_id`

## รัน Normalize

```bash
python normalized.py \
  --input alerts.jsonl \
  --output normalized.csv \
  --ground-truth ground_truth_manual.csv
```

ระบบจะสร้าง `ground_truth_manual.csv` ที่ยังไม่มีคำตอบ ให้เปิดแล้วกรอกเฉพาะ:

```text
manual_label   = Safe / Suspicious / Dangerous
incident_id    = เหตุการณ์ชุดเดียวกันใช้ ID เดียวกัน
attack_type    = ชนิดเหตุการณ์ที่ผู้ตรวจระบุ
confidence     = low / medium / high
label_reason   = หลักฐานที่ใช้ตัดสิน
reviewer       = ผู้ตรวจ
review_status  = approved เมื่อยืนยันแล้ว
```

ตัวอย่าง Safe หลายแถวที่เกิดในช่วงใช้งานปกติเดียวกันใช้ `incident_id=benign-session-001`
ส่วนเหตุการณ์โจมตีชุดเดียวกันใช้ `incident_id=incident-attack-001`

## รัน Rule-based

```bash
python rulebase.py --input normalized.csv --output-dir routed
```

Rule ใช้ `rule_id`, `rule_level`, `rule_groups` และ `rule_count` เท่านั้น

## Train

```bash
python ml_train.py \
  --input routed/ml_candidates.csv \
  --ground-truth ground_truth_manual.csv \
  --output-dir model
```

`manual_label` และ `incident_id` ใช้เป็นคำตอบและตัวแบ่งชุดข้อมูลเท่านั้น ไม่เข้า ML Features
