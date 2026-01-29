# Election1: Machine Notes

## Recon

### Nmap
- Port 22/tcp: SSH
- Port 80/tcp: HTTP (Apache 2.4.29)

### Web Enumeration
- Found `/election/` directory.
- Found sensitive logs at `http://[IP]/election/admin/logs/`.
- Log entry: `[2020-01-01 00:00:00] Assigned Password for the user love: P@$$w0rd@123`.

## Initial Access

### SSH (love)
- Logged in via SSH: `love` : `P@$$w0rd@123`.

## Privilege Escalation

### SUID Enumeration
- Checked for SUID binaries:
```bash
find / -perm -4000 -type f 2>/dev/null | grep -v proc
```
- Found unusual SUID: `/usr/local/Serv-U/Serv-U`.

### Serv-U LPE (Exploit)
- Checked Serv-U version; potentially vulnerable to LPE (Serv-U 15.1.7).
- Downloaded and compiled exploit (e.g., `test.c` for Serv-U LPE):
```bash
gcc exploit.c -o exploit
./exploit
```
- Result: **Root shell**.
