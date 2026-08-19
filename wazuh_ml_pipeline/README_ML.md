# Wazuh ML Pipeline - คู่มือใช้งาน

ชุดไฟล์นี้สร้าง Dataset, ฝึก XGBoost และจัดลำดับความสำคัญของ Wazuh Alert เป็น
`Safe`, `Suspicious` และ `Dangerous` โดยแยกข้อมูล Provenance/Marker ออกจาก
Feature เพื่อป้องกัน Data Leakage

## ไฟล์ในชุด

- `prepare_dataset.py` อ่าน `alerts.json` และสร้าง Behavioral Features
- `train_model.py` แบ่ง Train/Test ตาม `operation_id` และฝึก XGBoost
- `predict_alerts.py` ทำนาย Alert ใหม่และคำนวณ Priority 0-100
- `wazuh_project_rules.xml` กฎสำหรับ Log จำลองจาก `wazuh_log_generator.py`
- `asset_importance.example.json` ตัวอย่างคะแนนความสำคัญของเครื่อง 1-10
- `requirements.txt` Python packages

## 1. เตรียม Python

แนะนำ Python 3.10 ขึ้นไป และ Virtual Environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
```

## 2. ติดตั้งกฎและตั้งค่า Wazuh

ทำบน Wazuh Manager:

```bash
sudo cp wazuh_project_rules.xml /var/ossec/etc/rules/wazuh_project_rules.xml
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager
```

บนเครื่อง Wazuh Agent ให้เพิ่มใน `/var/ossec/etc/ossec.conf`:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/opt/wazuh-lab/events.jsonl</location>
</localfile>
```

จากนั้น:

```bash
sudo mkdir -p /opt/wazuh-lab
sudo touch /opt/wazuh-lab/events.jsonl
sudo chown "$USER" /opt/wazuh-lab/events.jsonl
sudo systemctl restart wazuh-agent
```

ก่อนใช้จริงควรทดสอบกฎบน Manager:

```bash
sudo /var/ossec/bin/wazuh-logtest
```

นำ JSON หนึ่งบรรทัดจาก `events.jsonl` ไปวาง แล้วตรวจว่าตรงกับ Rule ID
`100100-100106`

## 3. สร้าง Golden Dataset หลายรอบ

รัน `wazuh_log_generator.py` จากโฟลเดอร์หลัก โดยเขียน Event เข้าไฟล์ที่ Agent
เฝ้าดู และรวม Label ไว้ในไฟล์แยก:

```bash
python3 wazuh_log_generator.py \
  --profile mixed \
  --noise-count 200 \
  --scan-count 40 \
  --web-scan-count 30 \
  --failed-login-count 25 \
  --operation-id op-001 \
  --output /opt/wazuh-lab/events.jsonl \
  --labels data/labels.jsonl
```

รอบถัดไปต้องใช้ `operation_id` ใหม่และ `--append`:

```bash
python3 wazuh_log_generator.py \
  --profile mixed \
  --noise-count 240 \
  --scan-count 25 \
  --web-scan-count 45 \
  --failed-login-count 35 \
  --operation-id op-002 \
  --output /opt/wazuh-lab/events.jsonl \
  --labels data/labels.jsonl \
  --append
```

ควรสร้างอย่างน้อย 20-30 รอบ และเปลี่ยนจำนวน Noise/Attack ในแต่ละรอบ
อย่าใช้ `operation_id` ซ้ำ

`events.jsonl` ใช้ส่งเข้า Wazuh ส่วน `labels.jsonl` เป็นเฉลยในแล็บเท่านั้น
ห้ามตั้งค่าให้ Wazuh อ่าน `labels.jsonl`

## 4. นำ alerts.json ออกจาก Wazuh Manager

Alert หลักอยู่ที่:

```text
/var/ossec/logs/alerts/alerts.json
```

คัดลอกเฉพาะไฟล์ที่เกี่ยวข้องกับการทดลองมาไว้ในโฟลเดอร์ทำ ML เช่น:

```bash
sudo cp /var/ossec/logs/alerts/alerts.json data/alerts.json
sudo chown "$USER" data/alerts.json
```

ตรวจสอบว่า `event_id` และ `operation_id` ยังปรากฏอยู่ใน `data.*` หรือ
`full_log` ของ Alert เพราะสอง Field นี้ใช้เชื่อม Alert กับ Label

## 5. สร้าง Dataset

```bash
python3 wazuh_ml_pipeline/prepare_dataset.py \
  --alerts data/alerts.json \
  --labels data/labels.jsonl \
  --asset-map wazuh_ml_pipeline/asset_importance.example.json \
  --output data/dataset.csv
```

Behavioral Features ที่สร้างให้อัตโนมัติ ได้แก่:

- `source_events_previous_5m`
- `failed_logins_previous_10m`
- `scans_previous_5m`
- `unique_actions_previous_10m`
- `previous_stage_max_30m`
- `chain_length_previous_30m`
- เวลา, Rule Level, MITRE, Asset Importance และประเภทเหตุการณ์

สคริปต์จะไม่ส่งออก IP, Username, Provenance หรือ Lab Session เป็น Feature

ถ้ามี Alert เชื่อมกับ Label ไม่ได้ โปรแกรมจะหยุด เพื่อป้องกัน Dataset ผิด
ให้ตรวจ `event_id` ก่อน ไม่ควรแก้ด้วย `--allow-unlabeled` ตอนสร้าง Train Dataset

## 6. ฝึกและประเมิน Model

```bash
python3 wazuh_ml_pipeline/train_model.py \
  --dataset data/dataset.csv \
  --output-dir artifacts
```

ผลลัพธ์:

```text
artifacts/wazuh_xgboost.joblib
artifacts/metrics.json
artifacts/confusion_matrix.csv
artifacts/test_predictions.csv
```

โปรแกรมแบ่งข้อมูลด้วย `operation_id` จึงไม่ปล่อย Alert จากการทดลองรอบเดียวกัน
ไปอยู่ทั้ง Train และ Test พร้อมใช้ Balanced Sample Weight แก้ Class Imbalance

ค่าที่ควรพิจารณาหลัก:

1. `Dangerous recall`
2. `Macro F1`
3. จำนวน Dangerous ที่ถูกทำนายเป็น Safe ใน Confusion Matrix

Accuracy สูงเพียงอย่างเดียวไม่เพียงพอ

## 7. ทำนาย Alert ชุดใหม่

สร้าง CSV ที่ไม่มี Label:

```bash
python3 wazuh_ml_pipeline/prepare_dataset.py \
  --alerts data/new_alerts.json \
  --asset-map wazuh_ml_pipeline/asset_importance.example.json \
  --allow-unlabeled \
  --output data/inference.csv
```

ทำนายและคำนวณ Priority:

```bash
python3 wazuh_ml_pipeline/predict_alerts.py \
  --model artifacts/wazuh_xgboost.joblib \
  --dataset data/inference.csv \
  --output predictions/prioritized_alerts.csv
```

ไฟล์ผลลัพธ์มี Probability ของทุก Class, `priority_score` และระดับ
`Low/Medium/High/Critical`

## 8. ใช้กับข้อมูลจริง

ก่อนอ้างผลเป็นผลการทดลองจริง:

1. ใช้ Log ที่ Wazuh สร้าง Alert จริง ไม่ใช้ Event จำลองโดยตรง
2. สร้างอย่างน้อย 20-30 Operations
3. กัน Operations บางรอบไว้เป็น Test Set
4. ห้ามใช้ Marker เช่น `atk_admin`, `10.99.99.10`, `atk_*.php`, Provenance
   หรือ Lab Session เป็น Feature
5. ตรวจ Label กับสมุดบันทึก Caldera/Atomic Red Team และรายงาน Detection Gap
6. ปรับ `asset_importance` ให้ตรงกับระบบจริง
7. ปรับสูตร Priority หลังได้ผล Validation จริง

## ปัญหาที่พบบ่อย

### เชื่อม Label ไม่ได้

ตรวจว่า Wazuh Alert มี `event_id` เดียวกับ `labels.jsonl` ถ้า `full_log` ถูกตัด
ออกจาก Rule ให้เอา `<options>no_full_log</options>` ออก

### Training split ขาดบาง Class

เพิ่มจำนวน Operations หรือเปลี่ยน `--test-size`/`--seed` ห้ามแก้ด้วยการสุ่ม Alert
จาก Operation เดียวกันปนกัน

### Rule XML ไม่ผ่าน

ใช้คำสั่งนี้ก่อน Restart ทุกครั้ง:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
```

ถ้ามี Rule ID ชนกับ Rule เดิม ให้เปลี่ยนช่วง `100100-100106` เป็นช่วง Local Rule
ID ที่ยังไม่ถูกใช้ทั้งไฟล์
