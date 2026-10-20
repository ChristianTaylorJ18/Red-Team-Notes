## Web Reconnaissance

Once you have a host running HTTP(S), the goal is to discover every endpoint, vhost, subdomain, technology, and (where in scope) WAF before sending a single payload.

---

### Setup

```bash
## Map hostnames in /etc/hosts so vhosts resolve
echo "10.129.93.57 app.inlanefreight.local" | sudo tee -a /etc/hosts

## Sanity check
curl -I http://<target>
whatweb http://<target>
nmap -sV -sC -Pn <target>
```

### Tech Fingerprinting

```bash
curl -I http://<target>                      # basic server / framework headers
whatweb app.inlanefreight.local              # CMS / tech stack
wafw00f inlanefreight.com                    # WAF detection
nikto -h app.inlanefreight.local -port <p> -Tuning b   # OS + low-hanging vulns
```

For deep crawling and source-code extraction (forms, JS endpoints, comments):

```bash
python3 ReconSpider.py http://inlanefreight.com
cat results.json
```

### Directory & Content Fuzzing

#### gobuster

```bash
gobuster dir -u https://<target> -w /usr/share/wordlists/common.txt
gobuster dir -u https://<target> -w /usr/share/wordlists/common.txt -x php,html,txt
```

#### ffuf

> Errors mean you typed it in wrong — `ffuf` is unforgiving about the position of `FUZZ` and the placement of `:FUZZ` keyword markers.

Directory fuzz:

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt \
     -u http://SERVER_IP:PORT/FUZZ -ac
```

Fuzz file extensions onto a known filename:

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ \
     -u http://SERVER_IP:PORT/blog/indexFUZZ
```

Fuzz filenames under a known extension:

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ \
     -u http://SERVER_IP:PORT/blog/FUZZ.php
```

Recursive fuzzing (descend into discovered directories):

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ \
     -u http://SERVER_IP:PORT/FUZZ \
     -recursion -recursion-depth 1 -e .php -v -ic
```

> Every new domain or subdomain you find — add it to `/etc/hosts` before fuzzing it. Wildcard DNS will silently break results otherwise.

#### Wordlists to know

```bash
/usr/share/wordlists/dirb/common.txt
/usr/share/seclists/Discovery/Web-Content/
/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
```

Default-creds wordlist (useful early on):
<https://github.com/danielmiessler/SecLists/tree/master/Passwords/Default-Credentials>

### vhost / Subdomain Fuzzing

```bash
## Subdomain — public DNS-style
ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
     -u https://FUZZ.inlanefreight.com/

## vhost — internal hosts that share an IP, switched on Host header
ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
     -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb'

## Filter once you know the wildcard size
ffuf -u http://<ip> -H "Host: FUZZ.<domain>" -w <wordlist> -fs 157 -ac -t 100
```

> Reminder: **vhosts can have vhosts**. Re-fuzz any new domain you discover. And don't forget to add discovered vhosts to `/etc/hosts` with the IP of the main website.

### Parameter Fuzzing

Useful when an endpoint takes hidden GET/POST parameters you have to guess.

#### GET parameters

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
     -u http://admin.academy.htb:PORT/admin/admin.php?FUZZ=key -ac
```

#### POST parameters

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
     -u http://admin.academy.htb:PORT/admin/admin.php \
     -X POST -d 'FUZZ=key' \
     -H 'Content-Type: application/x-www-form-urlencoded' -ac
```

#### Brute-force values for a discovered parameter (e.g. numeric `id`)

```bash
## Build the ID list
for i in $(seq 1 1000); do echo $i >> ids.txt; done

## PHP requires the form content-type
ffuf -w ids.txt:FUZZ \
     -u http://admin.academy.htb:PORT/admin/admin.php \
     -X POST -d 'id=FUZZ' \
     -H 'Content-Type: application/x-www-form-urlencoded' -ac

## Confirm a hit with curl
curl -X POST http://admin.academy.htb:32543/admin/admin.php \
     -d 'id=73' -H 'Content-Type: application/x-www-form-urlencoded'
```

### FinalRecon (one-shot)

```bash
git clone https://github.com/thewhiteh4t/FinalRecon.git && cd FinalRecon
pip3 install -r requirements.txt --break-system-packages

## Patch line 201 if it errors:
## parsed_url.top_domain_under_public_suffix → parsed_url.registered_domain

chmod +x ./finalrecon.py
./finalrecon.py --headers --sslinfo --whois --crawl --dns --sub --dir --full \
    --url http://inlanefreight.com > output.txt
```

Flag reference:

| Flag | Purpose |
|------|---------|
| `--headers` | Header info |
| `--sslinfo` | SSL certificate info |
| `--whois` | Whois lookup |
| `--crawl` | Crawl the site |
| `--dns` | DNS enumeration |
| `--sub` | Subdomain enumeration |
| `--dir` | Directory search |
| `--wayback` | Wayback URLs |
| `--ps` | Fast port scan |
| `--full` | All of the above |

### HTTP Verb Tampering

`403 Forbidden` may only apply to one verb — try them all:

```bash
curl -X GET    http://<target>/admin
curl -X POST   http://<target>/admin
curl -X PUT    http://<target>/admin
curl -X DELETE http://<target>/admin
curl -X TRACE  http://<target>/admin
```

Also try header tricks:

```bash
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Forwarded-For: 127.0.0.1
```

### curl Quick-Ref

```bash
curl -v http://<target>                                       # verbose with headers
curl -b "PHPSESSID=abc" http://<target>                        # send cookie
curl -d 'user=admin&pass=admin' http://<target>/login          # POST form
curl -H 'Content-Type: application/json' -d '{"k":"v"}' http://<target>/api   # POST JSON
curl -F 'file=@shell.php' http://<target>/upload.php           # file upload
curl -L http://<target>                                        # follow redirects
curl -k https://<target>                                       # ignore SSL
```

### Spidering with Burp

Use Burp's Target → Sitemap to passively map everything your browser hits, then promote interesting requests to Repeater/Intruder. See [Web Proxies](../2-pre-exploitation/02-web-proxies.md).
