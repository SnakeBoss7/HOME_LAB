# Splunk Custom Alert Action Setup Guide

> **App Name:** `soar_mini`  
> **Script:** `soar_flow.py`

---

## 1. App Directory Structure

```text
/opt/splunk/etc/apps/soar_mini/
├── bin/
│   ├── soar_flow.py              # Main Python script
│   └── vendor/                   # Dependencies (jira, requests, etc.)
├── default/
│   ├── alert_actions.conf        # Alert action definition
│   └── app.conf                  # App metadata
├── metadata/
│   └── default.meta              # Permissions
└── README/
    └── alert_actions.conf.spec   # (Optional) Documentation
```

---

## 2. Install Dependencies

Install required Python packages to the vendor directory:

```bash
sudo pip3 install -t /opt/splunk/etc/apps/soar_mini/bin/vendor jira requests splunklib python-dotenv pycryptodome
```

> **Note:** Use `jira==3.5.2` if running Python 3.9 (Splunk's default)

---

## 3. Configuration Files

### 3.1 `app.conf`

**Template:**
```ini
[install]
is_configured = 0

[ui]
is_visible = true
label = <App Display Name>

[launcher]
author = <your_name>
description = <App description>
version = 1.0.0
```

**My Configuration:**
```ini
#
# Splunk app configuration file
#

[install]
is_configured = 0

[ui]
is_visible = true
label = SoarWorkflow

[launcher]
author = insaen 
description = soar min Workflow 
version = 1.0.0
```

---

### 3.2 `alert_actions.conf`

**Template:**
```ini
[<script_name_without_extension>]
is_custom = 1
label = <Display Name in Splunk UI>
description = <What the alert does>
icon_path = <icon_filename>.png
payload_format = json
```

**My Configuration:**
```ini
[soar_flow]
is_custom = 1
label = My Custom Logger
description = Writes alert data to a local log file
icon_path = alerticon.png
payload_format = json
```

---

## 4. Python Script

**File:** `/opt/splunk/etc/apps/soar_mini/bin/soar_flow.py`

After creating/pasting the script, set proper permissions:

```bash
sudo chown splunk:splunk /opt/splunk/etc/apps/soar_mini/bin/soar_flow.py
sudo chmod +x /opt/splunk/etc/apps/soar_mini/bin/soar_flow.py
```

### Minimal Debug Script

```python
import sys
from datetime import datetime

# Debug logging
def log_debug(msg):
    try:
        with open("/tmp/soar_debug.log", "a") as f:
            f.write(f"[{datetime.now()}] {msg}\n")
        sys.stderr.write(f"SOAR: {msg}\n")
    except:
        pass

log_debug("=== Script Started ===")
log_debug(f"Arguments: {sys.argv}")
```

---

## 5. Credential Management (Splunk Password Store)

### Check Stored Credentials

```
https://localhost:8089/servicesNS/nobody/soar_mini/storage/passwords
```

### Add New Credential

```bash
curl -k -u <splunk_username>:<splunk_password> \
  -X POST 'https://localhost:8089/servicesNS/nobody/soar_mini/storage/passwords' \
  -d name=<credential_name> \
  -d password=<secret_value> \
  -d realm=<realm_name>
```

**Example realms used:**
| Realm | Username | Purpose |
|-------|----------|---------|
| `soar_jira_credentials` | `insaen` | Jira API Token |
| `soar_nvidia_credentials` | `nv` | NVIDIA NIM API Key |
| `soar_virusT_credentials` | `vt` | VirusTotal API Key |

---

## 6. Debugging

View real-time debug logs:

```bash
sudo tail -f /tmp/soar_debug.log
```

Check Splunk's internal logs:

```bash
sudo tail -f /opt/splunk/var/log/splunk/splunkd.log | grep -i soar
```

---

## 7. Restart Splunk After Changes

```bash
sudo /opt/splunk/bin/splunk restart
```