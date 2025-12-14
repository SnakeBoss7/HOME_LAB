# T1550.003/T1550.002 - PASS THE HASH & PASS THE TICKET

> **MITRE ATT&CK Technique:** Generally used for lateral Movement
This attack focuses on **Lateral Movent** to extract account credentials and use it for remote access 

---

##  What is PTH & PTT
This attacks Involves **Lsass.exe** Credential theft for gaining either the **kerberos** Ticket or the **NTLM** password Hash to gain other account access over the network,After Pass-the-Hash or Pass-the-Ticket, Windows automatically reuses the stolen credentials for network authentication, enabling lateral movement without requiring the plaintext password.

---
## Detection
### key points
- Lsass.exe Access
- Login Activity Immediately

### Key Detection Indicators
#### AD Security Events
- **Event ID 4624 (Logon):** Look for **Logon Type 3** (Network)
- **Event ID 4648 (Explicit Credential Logon):** A logon was attempted using explicit credentials.
- **Event ID 4768/4769 (Kerberos):** Watch for TGT/TGS requests with unusual encryption types (e.g., RC4/0x17) which might indicate a forged ticket (Golden/Silver Ticket) or PtT.

#### Sysmon Events
- **Event ID 10 (Process Access):** Monitor for processes accessing `lsass.exe`.
  - *TargetImage:* `C:\Windows\system32\lsass.exe`
  - [T1003.001-Playbook](../../T1003.001-Playbook)


> **NOTE:** I was doing T1550.002 which is Pass the hash but my system automatically chose to do kerberoast Auth before it was eligible to do so 