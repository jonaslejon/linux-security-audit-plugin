# TLS ciphers and mutual TLS

## Why this needs active testing

Configuration tells you what was *intended*. What a server actually negotiates depends on its TLS
library version, that library's compiled-in defaults, the distro's crypto policy
(`update-crypto-policies` on RHEL, `SECLEVEL` in Debian's OpenSSL config), and which directives the
effective config actually reached. A vhost with no `ssl_protocols` line is not "unknown" — it is
whatever the build defaults to, and that varies.

So: **read the config to know the intent, probe the endpoint to know the truth.** The collector
does both and tags each result `passive` or `active`. Where they disagree, the probe wins.

The probe is loopback-only and sends nothing but a ClientHello. For a public endpoint, confirm from
outside as well — `testssl.sh <host>:<port>` or SSL Labs — because a CDN, load balancer or reverse
proxy in front of the host terminates TLS with its own settings, and the origin's config then tells
you nothing about what clients actually get.

## Cipher and protocol policy

| Requirement | Why |
|---|---|
| TLS 1.2 minimum, TLS 1.3 preferred | SSLv3/TLS 1.0/1.1 are broken (POODLE, BEAST) and fail every compliance regime |
| AEAD only — AES-GCM, ChaCha20-Poly1305, AES-CCM | CBC-mode suites carry the Lucky13 / padding-oracle class of attack |
| Forward secrecy always — ECDHE or DHE | Static RSA key exchange (`kRSA`) means one stolen private key decrypts **all previously recorded traffic**. This is the single most consequential cipher finding |
| DH parameters ≥ 2048 bits | Logjam |
| No `aNULL` | Anonymous key exchange is encrypted but **unauthenticated** — an on-path attacker is invisible |
| No `eNULL`/`NULL` | Authenticated but **not encrypted** |
| No RC4, DES, 3DES, EXPORT | Broken or 64-bit-block (Sweet32) |
| No MD5 or SHA-1 MACs | Forgeable |
| Certificate: RSA ≥ 2048 or ECDSA P-256+, SHA-256 signature, SAN present, > 14 days to expiry | |

A good starting point is the Mozilla "intermediate" profile; use "modern" (TLS 1.3 only) where the
client base allows. On RHEL-family systems prefer `update-crypto-policies --set DEFAULT:NO-SHA1` (or
`FUTURE`) so the policy applies system-wide instead of per-daemon.

The collector probes each family individually (`tls.<port>.weak.<family>`) rather than reading the
cipher string, because a cipher string that *looks* restrictive can still permit a weak suite
through the library's defaults.

## Mutual TLS for internal tunnels

**Ordinary TLS authenticates the server to the client and nobody to the server.** For a public
website that is correct: the client is an anonymous browser. For an internal machine-to-machine
link it is not — it means any host that can reach the port is trusted, and the "encrypted tunnel"
between your services stops an eavesdropper but not an impostor.

So the rule for anything internal — service-to-service, agent-to-collector, node-to-node,
cross-datacentre, over a VPN or private VPC — is **mutual TLS with strict verification on both
ends**:

1. The server requires a client certificate and validates it against a specific CA
   (not the system trust store, which contains hundreds of public roots).
2. The client validates the server certificate **and** its hostname against that same private CA.
3. Both ends reject on failure rather than logging and continuing.

The collector classifies each TLS listener by bind address — loopback, internal (RFC1918/ULA),
wildcard, or external — and treats a missing client-certificate requirement on an internal or
wildcard listener as a finding, while leaving public listeners alone.

### Requested is not required

The most common mTLS defect is a server that *asks* for a client certificate but completes the
handshake anyway when none is presented. That authenticates nobody while looking like mTLS in the
config. The collector detects this by connecting without a client certificate and observing whether
the handshake is refused:

| Result | Meaning |
|---|---|
| `PASS` — required | The handshake was refused. Enforcement is real |
| `WARN` — requested but NOT enforced | A CertificateRequest was sent, but the connection succeeded without a certificate. Either enforcement is off, or the application is expected to check (nginx `$ssl_client_verify`, Apache `SSLVerifyClient require`) — verify that it actually does |
| no request | The server never asks. On an internal listener this is the finding |

Detection caveat: under TLS 1.3 some libraries (LibreSSL in particular) print no
CertificateRequest information at all, so the collector retries over TLS 1.2, where the signal is
reliable. If both are inconclusive, fall back to the configuration table below.

### The verification-enforcement setting, per service

The pattern to look for is the same everywhere: one setting turns TLS *on*, a **different** setting
turns peer *verification* on. Encryption without the second is the trap.

| Service | Encryption | Verification / mTLS enforcement |
|---|---|---|
| **Docker daemon** | `--tls` | `--tlsverify` + `--tlscacert`. `--tls` alone leaves the TCP API **encrypted but unauthenticated — remote root** |
| **nginx (server)** | `ssl_certificate` | `ssl_verify_client on` + `ssl_client_certificate`. `optional` requires an application-level `$ssl_client_verify` check |
| **nginx (to upstream)** | `proxy_pass https://` | `proxy_ssl_verify on` + `proxy_ssl_trusted_certificate`. **Verification is OFF by default** — the hop to the backend is MITM-able out of the box |
| **Apache (server)** | `SSLEngine on` | `SSLVerifyClient require` + `SSLCACertificateFile` |
| **Apache (proxy)** | `SSLProxyEngine on` | `SSLProxyVerify require` + `SSLProxyCheckPeerName on` |
| **HAProxy (frontend)** | `bind … ssl crt` | `verify required ca-file …` |
| **HAProxy (backend)** | `server … ssl` | `verify required ca-file …`. Defaults to `verify none` |
| **rsyslog** | `StreamDriver="gtls"` | `StreamDriverAuthMode="x509/name"` + `PermittedPeers`. `anon` = encrypted, unverified |
| **stunnel** | `cert`/`key` | `verifyChain = yes` + `CAfile`, plus `checkHost`. No verification by default |
| **PostgreSQL** | `ssl = on` | `hostssl … clientcert=verify-full` in `pg_hba.conf` |
| **MySQL/MariaDB** | `ssl_cert` | `require_secure_transport=ON` + per-user `REQUIRE X509` |
| **MongoDB** | `net.tls.mode: requireTLS` | `net.tls.CAFile` + `allowConnectionsWithoutCertificates: false` |
| **Redis** | `tls-port` | `tls-auth-clients yes` (the default — check it has not been turned off), and `port 0` to disable the plaintext port |
| **etcd** | `--cert-file` | `--client-cert-auth` and `--peer-client-cert-auth` |
| **OpenVPN** | `cert`/`key` | `remote-cert-tls server` / `verify-x509-name` on the client — without it, one client's certificate can impersonate the server to another client |
| **LDAP client** | `ldaps://` | `TLS_REQCERT demand` — `never`/`allow` sends credentials to anyone |
| **Postfix (outbound)** | `smtp_tls_security_level = may` | `verify` or `secure` for an internal relay; `may` does not validate the certificate |

### Client-side verification switched off

The quietest TLS failure is a client that does not check the certificate. It looks like TLS in
every diagram and provides no authentication at all. The collector greps cron jobs, systemd units,
profile scripts and local binaries for:

`curl -k` / `--insecure`, `wget --no-check-certificate`, `NODE_TLS_REJECT_UNAUTHORIZED=0`,
`PYTHONHTTPSVERIFY=0`, `GIT_SSL_NO_VERIFY`, `verify=False` (Python requests),
`rejectUnauthorized: false` (Node), `CURLOPT_SSL_VERIFYPEER => false` (PHP),
`InsecureSkipVerify: true` (Go), `check_certificate = off`.

Each hit is a real finding: that connection is encrypted against a passive eavesdropper and wide
open to an active one. The usual cause is a self-signed internal certificate that someone worked
around — the fix is to add the internal CA to the trust store (or pin it), not to keep the flag.

### Locally added CA certificates

Every root CA in the trust store can mint a valid certificate for **any** domain. Enumerate
`/usr/local/share/ca-certificates/` and `/etc/pki/ca-trust/source/anchors/` and justify each entry —
a legitimate internal CA belongs there, but so does an interception proxy's CA, and adding one is a
known persistence and traffic-interception technique.
