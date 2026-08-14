# Web servers, TLS, PHP, and listening-port exposure

## Listening ports

Every socket bound to a non-loopback address is directly reachable attack surface. For each one
answer three questions, in order:

1. **Does it need to listen at all?** Stop the service if not.
2. **Does it need to be non-loopback?** Databases, caches, metrics exporters, admin panels and
   container APIs almost always should bind `127.0.0.1` (or a VPN/private interface) and be reached
   through a proxy or tunnel. Changing a bind address is far more reliable than firewalling it.
3. **If it must be public, is it authenticated, patched, and rate-limited?**

Collect with `ss -tulpn`. Two things to check beyond the obvious list:

- **`0.0.0.0` / `[::]` binds.** A service bound to all interfaces on a multi-homed host (VPN,
  private network, cloud metadata network, container bridge) is reachable from every one of them,
  not just the one you were thinking of.
- **IPv6 asymmetry.** A service listening on `[::]` while the firewall rules were only written for
  IPv4 is a very common way a "closed" port is actually open.

### Ports that should essentially never face the internet

The collector flags these when they are bound off-loopback. The ones that most often turn into
full compromise:

| Port | Service | Why it is critical |
|---|---|---|
| 2375 | Docker API (plaintext) | Unauthenticated. `docker run -v /:/host` = instant root on the host. Treat an exposed 2375 as a compromise until proven otherwise |
| 2376 | Docker API (TLS) | Only safe if `--tlsverify` with client-certificate auth is actually enforced: TLS alone is encryption, not authentication |
| 6379 | Redis | Historically no auth by default; an unauthenticated Redis can be made to write an SSH key or a cron entry: reliable RCE |
| 9200 | Elasticsearch | Frequently deployed with security disabled: full read/write of all indexed data |
| 11211 | memcached | No auth, and a UDP amplification factor in the tens of thousands |
| 10250 | kubelet | Unauthenticated kubelet allows `exec` into any container on the node |
| 27017/3306/5432/1433 | MongoDB / MySQL / PostgreSQL / MSSQL | Direct database access; also the primary target of automated ransom sweeps |
| 445/139 | SMB | Worm and ransomware target |
| 111 | rpcbind | Enumerates RPC services and reflects UDP amplification |
| 161 | SNMP | Default community strings leak a full host inventory |
| 873 | rsync | Frequently unauthenticated and world-readable |
| 9100 | node_exporter | Full host telemetry, including process command lines |

Amplification/reflection services (`123` NTP, `161` SNMP, `111` rpcbind, `389` LDAP, `11211`
memcached, `53` DNS if recursive) matter even when *you* are not the victim: an open reflector
gets your host used in someone else's DDoS and your provider's abuse desk involved.

---

## NTP security

Two distinct concerns; audit both.

### As a client: can the time be manipulated?

Wrong time silently breaks security decisions: certificate expiry and revocation checks, TOTP/2FA,
Kerberos tickets, JWT `exp`, backup retention, and the ordering and credibility of logs during an
investigation. An on-path attacker who can move the clock forward can make a revoked or expired
certificate look valid, or expire a session store.

- **Use NTS** (Network Time Security, RFC 8915) where available: `chrony` with
  `server time.cloudflare.com iburst nts`. It authenticates the time source. Plain NTP is
  unauthenticated UDP and trivially spoofable by anyone on the path.
- **Use at least three independent sources.** With one source, that source *is* the clock. With
  three, chrony/ntpd can outvote a lying server.
- **Bound the step.** `makestep 1 3` (step only during the first three updates) rather than
  allowing unlimited stepping, so an attacker who transiently controls the source cannot jump the
  clock on a long-running host.
- `systemd-timesyncd` is a client-only SNTP implementation: no server surface, but also **no NTS in
  older versions and no source voting**: fine for a low-stakes host, weak where time is
  security-relevant. It supports NTS from systemd v257.

### As a server: is this host a reflector?

If `udp/123` is bound to a public address, the host answers NTP queries from the internet. That is
correct only if it is deliberately a time server. Otherwise it is attack surface and a DDoS
amplifier.

**ntpd**: the classic problem is mode 6/7 control queries and `monlist` (CVE-2013-5211), which
return far more data than the request. Require:

```
restrict default kod nomodify notrap nopeer noquery limited
restrict -6 default kod nomodify notrap nopeer noquery limited
restrict 127.0.0.1
restrict ::1
disable monitor
```

`noquery` blocks status/control queries; `disable monitor` kills `monlist` specifically.

**chrony**: safer defaults: it does not serve time unless an `allow` directive is present, and its
command port binds to loopback. Verify:
- No unintended `allow` line (and if serving, `allow 10.0.0.0/8`-style scoping, not `allow all`).
- `cmdport 0` if `chronyc` is never used remotely, or `bindcmdaddress 127.0.0.1`.
- `noclientlog` if serving many clients, to bound memory.

Firewall `udp/123` inbound unless the host is a time server; outbound is what a client needs.

---

## nginx

Read the **effective** config with `nginx -T`: it expands every `include`, which is where the
surprise directives live. `nginx -t` only validates.

| Control | Setting | Why |
|---|---|---|
| Version disclosure | `server_tokens off;` | Removes the version from the `Server` header and error pages, so mass scanners can't select targets by version |
| TLS versions | `ssl_protocols TLSv1.2 TLSv1.3;` | TLS 1.0/1.1 are deprecated and fail most compliance scans |
| Ciphers | `ssl_prefer_server_ciphers off;` with a Mozilla "intermediate" cipher list, or omit entirely on TLS 1.3-only | Server preference is no longer the recommendation |
| HSTS | `add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;` | Stops SSL-stripping downgrade. Start with a short max-age |
| Other headers | `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN` (or CSP `frame-ancestors`), `Referrer-Policy`, `Content-Security-Policy` | Note: `add_header` in a nested block **replaces** all inherited `add_header` directives: a per-location header silently drops the server-level security headers. Always re-declare, or use `always` |
| Directory listing | `autoindex off;` (the default; flag any explicit `on`) | |
| Rate limiting | `limit_req_zone` + `limit_req`, `limit_conn` | Brute force and application-layer DoS |
| Body size | `client_max_body_size` | Upload-based resource exhaustion |
| Timeouts | `client_body_timeout`, `client_header_timeout`, `send_timeout` | Slowloris |
| Hidden files | `location ~ /\. { deny all; }` | Blocks `.git`, `.env`, `.htaccess` retrieval |
| Real client IP | `set_real_ip_from <proxy CIDR>;` **before** `real_ip_header X-Forwarded-For;` | Without `set_real_ip_from`, any client can forge `X-Forwarded-For` and defeat rate limits, IP allowlists and fail2ban. This is a real vulnerability, not a nicety |
| Status endpoint | `stub_status` restricted to loopback | |

**PHP-FastCGI misconfiguration.** The dangerous pattern is a `location ~ \.php$` that passes any
path ending in `.php` to the PHP socket without confirming the file exists. Combined with an upload
directory, an attacker uploads `x.jpg/foo.php` (or similar) and gets code execution. Require
`try_files $uri =404;` inside the PHP location, and set `cgi.fix_pathinfo=0`.

---

## Apache

Read the effective config with `apachectl -S` (vhost map) and `apachectl -M` (loaded modules), then
the config tree.

| Control | Setting | Why |
|---|---|---|
| Version disclosure | `ServerTokens Prod`, `ServerSignature Off` | Default `Full` leaks Apache version, OS, and the version of every module |
| TRACE | `TraceEnable Off` | Cross-Site Tracing |
| Directory listing | remove `Indexes` from `Options` | |
| Default deny | `<Directory />` with `Require all denied` / `AllowOverride None`, then open up per-vhost | Stops a misconfigured alias from serving the filesystem root |
| `.htaccess` | `AllowOverride None` wherever possible | With `AllowOverride All`, anyone who can write into the served tree can change server behaviour: with `Options +ExecCGI` or a handler directive that is remote code execution. This is the standard escalation from "file upload bug" to "shell" |
| Symlinks | `Options -FollowSymLinks` or `+SymLinksIfOwnerMatch` | Symlink-following out of the docroot |
| Limits | `LimitRequestBody`, `LimitRequestFields`, `Timeout 60`, `KeepAliveTimeout 15` | Resource exhaustion, Slowloris |
| Headers | `Header always set …` for the same set as nginx | |
| TLS | `SSLProtocol -all +TLSv1.2 +TLSv1.3`, modern `SSLCipherSuite`, `SSLUseStapling on` | |
| User | `User www-data` / `Group www-data`, only the master is root | |

### Loaded modules vs *used* modules

A loaded module parses attacker-reachable input on every request whether or not a single site
uses it. Default distro module sets are far larger than any one site needs, so the useful question
is not "is `mod_dav` loaded" but **"is `mod_dav` loaded and unused"**: that is free attack surface
with no functionality to weigh against it.

The collector determines usage by looking for the directives each module provides, and reports
`loaded / used` vs `loaded / UNUSED`. One subtlety matters: the usage search deliberately excludes
`mods-enabled/` and `mods-available/`. Debian ships `DavLockDB` inside the packaged
`dav_fs.conf`, so searching the whole tree would make `mod_dav_fs` look used on every host that
merely has it enabled. A module counts as used only when a **site** uses it: `sites-enabled/`,
`conf-enabled/`, the main config, and `.htaccess`.

| Module | Proven used by | Why it matters when idle |
|---|---|---|
| `dav`, `dav_fs`, `dav_lock` | `Dav On` | HTTP write methods (PUT/DELETE/MOVE) against the docroot: the fastest route from "web server" to "attacker-uploaded webshell" |
| `status`, `info` | `SetHandler server-status`/`server-info` | live request URLs, client IPs, and the full effective config |
| `userdir` | `UserDir` | enumerates local accounts and serves files from home directories |
| `autoindex` | `Options +Indexes` | directory listings |
| `cgi`, `cgid` | `ScriptAlias`, `+ExecCGI` | arbitrary script execution (Shellshock class) |
| `include` | `Options +Includes`, `XBitHack` | SSI `<!--#exec-->`: with a writable docroot, direct RCE |
| `proxy*` | `ProxyPass`, `<Proxy` | the SSRF pivot; `ProxyRequests On` is an open proxy. `proxy_ajp` carries Ghostcat (CVE-2020-1938) |
| `lua` | `LuaHook*` | embedded code execution surface |
| `negotiation` | `Options +MultiViews` | MultiViews leaks file variants and has enabled source-disclosure bugs |
| `speling` | `CheckSpelling` | turns a 404 into a probe oracle for hidden files |
| `vhost_alias` | `VirtualDocumentRoot` | Host-header injection reaches other document roots |
| `asis` | `send-as-is` handler | serves raw unfiltered headers: header injection |

**nginx** modules come from two places, and both are checked: `load_module` lines (dynamic; remove
the line) and `nginx -V` build flags (compiled in: needs a different package or a rebuild, so at
minimum confirm no vhost can reach it). High-value idle modules: `dav` (`dav_methods`), `ssi`,
`autoindex`, `perl` (arbitrary code, and it blocks the event loop), `image_filter` (libgd decoder
surface driven by request parameters), `xslt` (libxslt: XXE and RCE), `mp4`/`flv` parsers,
`random_index`, `sub`/`addition` (body rewriting), plus whole extra protocol stacks if `mail` or
`stream` blocks exist.

**PHP extensions** are the same argument one layer down: each is C code parsing request input.
`xdebug` in production is the standout: a debugger that has repeatedly been turned into remote code
execution. `ffi` calls arbitrary native functions and defeats `disable_functions` and
`open_basedir` outright. `phar` provides the `phar://` deserialization gadget path. `imagick`
carries the ImageTragick lineage, and `exif` has a steady CVE record.

### Config file ownership

If the worker user can write the web server's config, or owns any file under `/etc/nginx`,
`/etc/apache2`, `/etc/httpd`, `/etc/php`, then a file-write bug becomes permanent RCE: the process
serving requests rewrites its own configuration and it takes effect on the next reload. The same
logic makes `AllowOverride All` plus a writable docroot dangerous, since `.htaccess` *is* config.

---

## TLS certificates and keys

- **Private key permissions** `600 root:root` (or `640 root:ssl-cert`). A key readable by the
  webserver's worker user means any file-read bug in the application discloses it.
- **Expiry**: flag anything inside 14 days. Expired certs cause outages *and* train users to click
  through warnings.
- **Key strength / signature**: RSA < 2048 or SHA-1 signatures are findings.
- **Renewal automation**: certbot/acme.sh timer present and last-run recent. A manually renewed
  certificate is a scheduled outage.
- **Validate externally** where the host is public: `testssl.sh` or SSL Labs gives chain,
  downgrade, and known-attack coverage that a config read cannot.

---

## PHP

| Setting | Want | Why |
|---|---|---|
| `expose_php` | `Off` | `X-Powered-By` gives the exact version to scanners |
| `display_errors` | `Off` (with `log_errors = On`) | Errors leak absolute paths, SQL, sometimes credentials |
| `allow_url_fopen` | `Off` | Turns many ordinary bugs into SSRF/remote file inclusion |
| `allow_url_include` | `Off` | Remote file inclusion → RCE |
| `cgi.fix_pathinfo` | `0` | With a permissive FastCGI location, uploads get executed as PHP |
| `disable_functions` | `exec,passthru,shell_exec,system,proc_open,popen,pcntl_exec` | A webshell needs one of these. Not a boundary (bypasses exist) but it removes the easy path |
| `open_basedir` | set per vhost | Confines file access; stops LFI from reaching `/etc`, keys, or a neighbouring site |
| `session.cookie_httponly` | `On` | XSS → session theft |
| `session.cookie_secure` | `On` | Session cookie over plaintext HTTP |
| `session.cookie_samesite` | `Lax` or `Strict` | CSRF |
| `session.use_strict_mode` | `On` | Session fixation |
| `file_uploads` / `upload_max_filesize` | off if unused, bounded if used | |

Also check the PHP **version** against [php.net's supported versions](https://www.php.net/supported-versions.php):
an EOL PHP branch gets no security fixes at all, which outranks every setting in this table.

**php-fpm pools**: each site should run in its own pool under its own user, with
`listen.owner`/`listen.group`/`listen.mode = 0660` so only that site's webserver can reach the
socket, and `security.limit_extensions = .php`. Shared-pool hosting means one compromised site
reads every other site's files and database credentials.

---

## Webroot hygiene

The highest-yield finding in this whole area: **is the document root writable by the user the web
server runs as?** If yes, any file-write bug becomes persistent code execution (a webshell), and
`AllowOverride All` makes it worse. Application code should be owned by a deploy user and readable,
not writable, by the web user, with narrow exceptions for genuine upload/cache directories,
which should themselves be `noexec`-served (a `location` that denies `.php` under `/uploads`).

### Evaluating "writable by the web server" correctly

Writability must be tested by **all three routes** (owner, group, and other) against the identity
that actually serves requests. Checking only the group and world bits is the common mistake and it
misses the most frequent real case: a directory **owned by `www-data` with mode 755** is fully
writable by `www-data`. Typical WordPress and Laravel deployments look exactly like that, and a
group/world-only check reports them clean.

So: resolve the worker user from the running processes (`nginx: worker`, `apache2 -k`,
`php-fpm: pool`), resolve its groups with `id -nG`, and match on
`(-user W -perm -u+w) -o (-group G -perm -g+w) -o -perm -o+w`. If the worker runs as **root**, the
question is moot, everything is writable, and that is the finding to report instead.

Three distinct results, ranked:

1. **Writable `.php`/`.phtml` files**: the worst. Existing application code is modified in place;
   no upload bug is needed and the change persists as a webshell.
2. **Writable directory + an active interpreter handler**: the webshell triad: writable,
   interpreted, web-reachable. Genuine upload and cache directories need a rule that stops the
   interpreter running there:
   - nginx: `location ~ ^/uploads/.*\.php$ { deny all; }` (or `return 403`)
   - Apache: `php_flag engine off` / `SetHandler None` / `RemoveHandler .php` in that directory
   The audit looks for such a guard per writable directory and reports the ones that lack it.
3. **Writable directory with no interpreter**, still an upload, defacement and malware-hosting
   primitive, but not direct code execution. Report it as the lesser finding it is.

A **writable `.htaccess`** deserves its own callout: the web process can re-enable the PHP handler
inside an upload directory, set a new handler, or remove an access restriction. Under
`AllowOverride All` that is equivalent to editing the vhost.

Scan depth matters: application trees are deep (`storage/framework/cache`, `wp-content/uploads`),
so a `maxdepth 2-3` scan misses most of them. And use POSIX `-print`, not GNU `-printf`: a find
without `-printf` returns nothing and the check silently passes.

Scan the docroot for things that must never be served: `.git/` (full source and often credentials
in history), `.env`, `*.sql` / `*.sql.gz` dumps, `*.bak` / `*.old` / editor swap files,
`wp-config.php.bak`, `phpinfo.php`, `adminer.php`, `id_rsa`, `.htpasswd`, `composer.lock`.
`.git/` exposure in particular is fully automated by scanners.

### .htaccess and .user.ini contents

These are configuration files that live *inside* the served tree, so anything able to write into
the webroot can change server behaviour. Presence and writability are not enough; audit what they
contain:

- **`auto_prepend_file` / `auto_append_file`**: the classic quiet webshell. Every PHP request in
  the tree first executes an attacker-chosen file. Check the referenced path.
- **`AddHandler` / `SetHandler` / `AddType` mapping to PHP or CGI**: how an uploaded `.jpg` is made
  executable, and how a handler-deny rule in an upload directory gets undone.
- **`php_value` / `php_admin_value`** touching `disable_functions`, `open_basedir`, `engine`:
  these can widen the setting, not only narrow it.
- **`Options +ExecCGI/+Includes/+FollowSymLinks/+Indexes`**: code execution, docroot escape, listing.
- **`RewriteRule ... [P]`**: the proxy flag turns the path into an SSRF primitive.
- **`Allow from all` / `Require all granted` / `Satisfy any`**: relaxes an inherited restriction;
  `Satisfy any` makes authentication optional when a host rule matches.
- **`AuthUserFile` pointing inside the docroot**, and `.htpasswd` files in the served tree: a
  downloadable password file. Also check the hash: 13-char `crypt()` and `$apr1$` (Apache-MD5) are
  trivially cracked; regenerate with `htpasswd -B` (bcrypt).

If `AllowOverride None` is set, `.htaccess` files are inert: establish that first, since it changes
the severity of everything above.
