# T1558.003 - Kerberoasting

> **MITRE ATT&CK Technique:** Steal  Kerberos Tickets: Kerberoasting

This attack focuses on **Kerberos ticket generation** to extract service account credentials.

---

##  What is Kerberos?

Kerberos is an **authentication protocol** commonly used in Active Directory environments. It operates on a **ticket-based system** — essentially a "pass" that grants access to services within the domain.

---

##  Prerequisites

| Requirement | Description |
|-------------|-------------|
| **Domain Users** | Valid user accounts in the Active Directory |
| **SPN (Service Principal Name)** | Services tied to user accounts (not computer accounts) |
| **Network Access** | Ability to communicate with the Domain Controller |

---

##  Ticket Flow: TGT & TGS

### TGT (Ticket Granting Ticket)
> *Generated once during initial authentication*

```
User  ──────────────►  KDC (Key Distribution Center)
         "Request TGT"

KDC   ──────────────►  User
         Returns TGT (encrypted with krbtgt account secret)
```

### TGS (Ticket Granting Service)
> *Generated for each service access request*

```
User + TGT  ─────────►  KDC
              "Request TGS for ServiceX"

KDC   ──────────────►  User
         Returns TGS (encrypted with service account password)
```

---

##  Why Kerberoasting Works

The **TGS ticket is encrypted using the service account's password hash**. This encrypted blob contains:

- Service name metadata etc
- **Service account password hash** ← *This is the target!*

Since the attacker receives this encrypted data, they can **crack the password offline** without triggering account lockouts or additional authentication attempts.

---

##  Encryption Types

| Type | Hex Code | Security Level |
|------|----------|----------------|
| **RC4-HMAC** | `0x17` |  Weak (easier to crack) |
| **AES128** | `0x11` |  Moderate |
| **AES256** | `0x12` |  Strong |

> **Note:** Attackers typically target services using **RC4-HMAC** encryption as it's significantly faster to crack compared to AES variants.

---

##  Detection Considerations

- Monitor for **Event ID 4769** (Kerberos Service Ticket Operations)
- Look for requests with encryption type `0x17` (RC4)
- Unusual service ticket requests from non-service accounts