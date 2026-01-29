# OSCP Required Tools Checklist

This list contains all tools mentioned in the `Commands_Reference.md` and `Decision_Matrix.md`. Ensure these are pre-compiled and ready in your toolkit.

## 1. Active Directory (Heavy Hitters)
- [ ] **Impacket Suite**: `secretsdump`, `ntlmrelayx`, `mssqlclient`, `getST`, `ticketer`.
- [ ] **NetExec**: `apt install netexec`
- [ ] **Certipy**: `pip3 install certipy-ad` (AD CS Exploitation)
- [ ] **BloodHound & SharpHound**: (GUI for pathing, .exe for data collection)
- [ ] **Rubeus.exe**: (Pre-compile for Kerberos abuse)
- [ ] **Mimikatz.exe**: (Credential dumping)
- [ ] **Kerbrute**: (User enumeration)
- [ ] **PyWhisker**: (Shadow Credentials)
- [ ] **BloodyAD**: (AD Object manipulation)

## 2. Windows Privilege Escalation (.exe)
- [ ] **PrintSpoofer.exe**: (SeImpersonate - Old)
- [ ] **GodPotato.exe**: (SeImpersonate - New)
- [ ] **SeManageVolumeExploit.exe**: (SeManageVolumePrivilege)
- [ ] **SharpGPOAbuse.exe**: (GPO Write access)
- [ ] **WinPEASany.exe**: (Auto-enumeration)
- [ ] **PsExec.exe**: (Sysinternals tool for lateral movement)
- [ ] **nc.exe**: (Standard Netcat for Windows)

## 3. Tunneling & Utilities
- [ ] **Chisel**: (Linux/Windows binaries for pivoting)
- [ ] **Socat**: (Relaying shells)
- [ ] **Ligolo-ng**: (Modern alternative to Chisel)
- [ ] **Strings.exe**: (Pre-exploitation recon)

## 4. Web & Enumeration
- [ ] **ffuf / Gobuster**: (Fuzzing)
- [ ] **Cadaver**: (WebDAV)
- [ ] **ntlm_theft.py**: (Capture NTLM via shares)

---

## 🛠️ Cross-Compilation Cheat Sheet
If you have a `.c` file and need a Windows `.exe`:

**Target 64-bit Windows:**
```bash
x86_64-w64-mingw32-gcc exploit.c -o exploit.exe -lntdll -lws2_32
```

**Target 32-bit Windows:**
```bash
i686-w64-mingw32-gcc exploit.c -o exploit.exe -lntdll -lws2_32
```

**Making a DLL:**
```bash
x86_64-w64-mingw32-gcc -shared -o output.dll input.c
```
