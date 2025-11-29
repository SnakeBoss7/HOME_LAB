# T1003.001 - OS Credential Dumping / LSASS Memory Dumping  


## What Is This Attack?

Attackers dump the memory of the LSASS process to steal credentials 
stored in RAM. LSASS (Local Security Authority Subsystem Service) holds:
- Login passwords
- NTLM hashes  
- Kerberos tickets

**One dump = All credentials on that machine**

## Why Attackers Use This

- Enables lateral movement (use stolen creds on other machines)
- Can crack passwords offline
- Used in: Ransomware, APT attacks, Cobalt Strike

## Real-World Examples

- **APT29 (SolarWinds):** Used comsvcs.dll method
- **Ryuk Ransomware:** Used ProcDump before encryption
- **Cobalt Strike:** Automated LSASS dumping module

## Attack Variations Tested

| Method | Tool | Difficulty | Stealth |
|--------|------|------------|---------|
| Test #1 | ProcDump | Easy | Low |
| Test #2 | rundll32 + comsvcs.dll | Easy | Medium |
| Test #8 | PowerShell (Out-Minidump) | Medium | High |


## Detection Summary

**All methods require:**
1. Accessing LSASS process memory
2. Creating a .dmp file

**We detect by monitoring:**
- EventID 10: Process accessing lsass.exe
- EventID 11: .dmp file creation
- EventID 1: Suspicious process execution

# 🔑 LSASS Dumping — Important Hex Values & Their Meaning

These are the **only four hex access values you actually need to remember** when analyzing LSASS access attempts (EDR/SIEM/SOC perspective).

---

## ✅ 0x1410  
### **Meaning:**  
`PROCESS_QUERY_INFORMATION` + `PROCESS_VM_READ`

### **Used By (Tools Detected):**  
- ProcDump  
- comsvcs.dll (COM+ Services)  
- Old Mimikatz versions  
- SQLDumper  

---

## ✅ 0x1000  
### **Meaning:**  
`only allows querying basic process information, not reading memory or extracting credentials`

### **Used By (Tools Detected):**  
- CompatelRunner.exe
- services.exe
---

## ✅ 0x1010  
### **Meaning:**  
`PROCESS_QUERY_LIMITED_INFO` + `PROCESS_VM_READ`

### **Used By (Tools Detected):**  
- Out-Minidump  
- Nanodump  
- Most **modern** LSASS dumping tools  

> 🔥 *This is the most common value used by stealthy/minimal-detection dumpers.*

---

## 🚨 0x1FFFFF  
### **Meaning:**  
`PROCESS_ALL_ACCESS` (FULL CONTROL)

### **Used By:**  
- Windows Task Manager LSASS dump  
- Some EDRs (when scanning LSASS)  
- PplDump (when exploiting PPL bypass)

> ⚠️ *Very suspicious if seen from a random process.*

---

## 🟡 0x40  
### **Meaning:**  
`PROCESS_QUERY_INFORMATION` **only**

### **Used By:**  
- `wmic`  
- `tasklist`  
- Many harmless system info tools

> ✔️ Safe to ignore — too common and noisy.

---

### 🎯 Summary Table

| Hex Value | Meaning | Tools / Behavior | Risk |
|----------|---------|------------------|------|
| **0x1410** | Query Info + VM Read | ProcDump, comsvcs, old Mimikatz | 🔥 High |
| **0x1010** | Limited Query + VM Read | Nanodump, Out-Minidump, modern dumpers | 🔥 High |
| **0x1FFFFF** | Full Access | Task Manager, PplDump, some EDRs | 🚨 Very High |
| **0x40** | Query Only | wmic, tasklist | 🟢 Safe/Noisy |

---



 With Defender ENABLED:

EventID 1: ✅ (maybe - depends on if it starts)
EventID 10: ✅ (you're seeing this)
EventID 11: ❌ (blocked before file created)

With Defender DISABLED:

EventID 1: ✅ (should see rundll32.exe)
EventID 10: ✅ (should see LSASS access)
EventID 11: ✅ (should see .dmp file)


