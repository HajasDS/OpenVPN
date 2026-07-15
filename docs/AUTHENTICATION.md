# Per-user authentication — architecture (v2)

Since v2.0.0 every VPN user has their **own** authentication mode, enforced
globally by an allowed-modes list. Users with different modes connect to the
**same** server at the same time.

| Mode | The user presents |
|---|---|
| `cert` | client certificate only |
| `password` | certificate + system password |
| `password_totp` | certificate + password + 6-digit TOTP code |
| `yubikey` | certificate + YubiKey OTP |
| `password_yubikey` | certificate + password + YubiKey OTP |

A valid client certificate is **always** required (`verify-client-cert
require` + CRL); the mode decides what must be presented *in addition*.

## The problem this design solves

OpenVPN has exactly **one** global PAM plugin and one `auth-user-pass-verify`
hook — there is no built-in per-client authentication policy. Additionally:

- with a PAM plugin configured, OpenVPN normally *requires* every client to
  send a username/password — which certificate-only users don't have;
- `auth-user-pass-verify` scripts run as the **unprivileged** user
  (`nobody`) after OpenVPN drops privileges, so a script can *never* verify
  passwords (no `/etc/shadow`), TOTP secrets or YubiKey API keys;
- the PAM plugin runs in a **privileged** helper forked before the privilege
  drop — it can verify credentials, but it knows nothing about which
  certificate is connecting.

The solution is two cooperating layers, both of which must approve every
connection (OpenVPN ANDs all verification methods):

```
client ──TLS── certificate check (CA + CRL, always)
         │
         ├── layer 1: auth-policy.sh          (unprivileged, fail-closed)
         │     policy file lookup by certificate CN:
         │       - CN must have a policy entry
         │       - the user's mode must be in the allowed list
         │       - username (if sent) must equal the CN
         │       - non-cert modes REQUIRE credentials
         │     never reads the password line
         │
         └── layer 2: openvpn-plugin-auth-pam.so   (privileged)
               ONE generated PAM stack, gated per user by group
               membership — verifies the actual credentials
```

## Layer 1: the policy gate

`server.conf` (always present in v2):

```
script-security 2
auth-user-pass-verify /etc/openvpn/server/auth-policy.sh via-file
auth-user-pass-optional
```

`auth-policy.sh` runs as `nobody` and reads
`/etc/openvpn/server/auth-policy.conf` (0644, **contains no secrets** — only
usernames and mode names):

```
allowed cert password_totp
default cert
user alice cert
user john password_totp
```

Decision matrix (everything else is DENY — fail closed):

| CN has entry | mode ∈ allowed | credentials sent | username == CN | result |
|---|---|---|---|---|
| no | – | – | – | **deny** (unknown certificate) |
| yes | no | – | – | **deny** (enforcement rules) |
| yes (cert) | yes | none | – | allow |
| yes (cert) | yes | yes | yes | allow (credentials ignored by policy) |
| yes (non-cert) | yes | none | – | **deny** (credentials required) |
| yes (non-cert) | yes | yes | yes | allow → PAM verifies the credentials |
| yes | yes | yes | no | **deny** (credential/certificate mixing) |

The script reads only the **username** line of the credentials file — the
password is never touched, logged or echoed by this layer.

`auth-user-pass-optional` lets certificate-only clients connect without
credentials; whether that is acceptable *for this particular certificate* is
exactly what the policy layer enforces.

## Layer 2: the gated PAM stack

One generated `/etc/pam.d/openvpn` (0600 — it can contain the YubiCloud API
key) serves all modes. Which credential modules run for a login is decided by
the user's membership of three system groups, kept in sync with the policy
file by the tool:

| group | members |
|---|---|
| `ovm-password` | users whose mode includes a password |
| `ovm-totp` | `password_totp` users |
| `ovm-yubikey` | `yubikey` and `password_yubikey` users |

Generated stack (blocks appear only for families actually in use):

```
auth    [success=done default=ignore]  pam_exec.so quiet .../pam-allow-empty.sh
auth    requisite                      pam_succeed_if.so quiet user ingroup openvpn-users
auth    [success=1 default=ignore]     pam_succeed_if.so quiet user notingroup ovm-yubikey
auth    requisite                      pam_yubico.so mode=client authfile=... try_first_pass ...
auth    [success=1 default=ignore]     pam_succeed_if.so quiet user notingroup ovm-password
auth    requisite                      pam_unix.so try_first_pass
auth    [success=1 default=ignore]     pam_succeed_if.so quiet user notingroup ovm-totp
auth    requisite                      pam_google_authenticator.so user=root secret=.../${USER}
auth    required                       pam_permit.so
account [success=done default=ignore]  pam_exec.so quiet .../pam-allow-empty.sh
account required                       pam_succeed_if.so quiet user ingroup openvpn-users
```

How to read it:

- `pam-allow-empty.sh` succeeds **only** for an empty `PAM_USER`. With
  `auth-user-pass-optional`, OpenVPN consults PAM with empty strings when a
  certificate-only client sends no credentials; this line short-circuits that
  to success. It is safe because layer 1 has already rejected empty
  credentials for every non-`cert` user.
- Each `notingroup` line **skips** the following credential module for users
  whose mode doesn't need it (`[success=1 …]` jumps over one line). Members
  fall through into the `requisite` module, which must succeed.
- Users in no gate group (cert-only users whose old client still sends
  credentials) pass straight to `pam_permit` — their credentials are
  irrelevant by policy; the certificate + CN match already authenticated them.
- Accounts are locked-down: `nologin` shell, no home, primary group
  `openvpn-users`; accounts of modes without a password factor are
  additionally password-**locked** (`usermod -L`).

### Credential transport per mode

| mode | client sends | PAM sees |
|---|---|---|
| `password` | username + password | `pam_unix` prompt answered with the password |
| `password_totp` | username + password, TOTP via `static-challenge` (SCRV1) | `pam_unix` gets the password, `pam_google_authenticator` gets the code |
| `yubikey` | username; the **password field is the YubiKey OTP** (one touch) | `pam_yubico` prompt answered with the OTP |
| `password_yubikey` | username; password field = password **immediately followed by a YubiKey touch** | `pam_yubico` (first) validates + strips the trailing OTP, passes the remaining password to `pam_unix` |

The append-the-OTP convention for `password_yubikey` is pam_yubico's native,
documented flow (the same one Yubico recommends for SSH). It replaced the
v1.x `static-challenge` transport because one server now serves both YubiKey
modes at once and the challenge channel is reserved for TOTP.
**v1.x `password_yubikey` profiles must be regenerated after migration.**

The plugin's prompt map in `server.conf` answers each PAM prompt from the
client's login fields (the plugin matches each pair name as a **substring**
of the PAM prompt):

```
plugin .../openvpn-plugin-auth-pam.so "openvpn ubi PASSWORD erification OTP assword PASSWORD ogin USERNAME"
```

Two deliberate quirks: each name has its first letter dropped so a single
pair matches either capitalisation (`assword` matches `Password:` and
`password:`), and `ubi` is listed first because pam_yubico's prompt embeds
the username (`YubiKey for 'alice':`) — matching it first means no username
content can misroute the answer. The map must stay short: OpenVPN parses at
most **16 tokens** per plugin line and silently truncates beyond that, and a
truncated (odd-length) list makes the plugin fail to initialize.

`auth-gen-token 43200` issues a session token so OTP users are not
re-challenged on hourly renegotiation.

## Enforcement rules

`Authentication → Global enforcement rules` maintains the allowed-modes list
(multi-select) and the default mode for new users:

- assigning a user a mode outside the list is **blocked** in the UI
  (with a one-tap jump to edit the list);
- the policy script rejects logins of non-compliant users at every
  connection attempt (fail-closed) — rules apply immediately;
- shrinking the list shows exactly which users become non-compliant and
  offers: update them now (guided, one by one), apply anyway (explicit
  default-No confirmation — they will be blocked), or cancel;
- selecting exactly one mode enforces it for everyone.

`Authentication → Validate authentication configuration` audits the whole
chain (policy file ↔ config ↔ groups ↔ accounts ↔ secrets ↔ PAM ↔
server.conf ↔ certificates) and lists every finding as PASS/WARN/FAIL.

## Changing a user's mode

`Authentication → User authentication modes → <user>` (or User management →
Per-user authentication settings). Order of operations on a change:

1. validate everything (`assign_<mode>` requirement check: packages, plugin,
   API credentials, user, certificate, enforcement rules) — problems show
   the standard fix menu, nothing hangs or half-applies;
2. summary + confirmation;
3. provision prerequisites (account, password, TOTP QR enrollment, YubiKey
   registration) — these are **inert** until the policy flips;
4. commit: gate groups + account lock state + policy entry together;
5. offer to delete now-unused enrollment data on downgrades (default: keep);
6. regenerate the `.ovpn` profile (the auth lines differ per mode).

If any provisioning step is cancelled, nothing is committed and the user
keeps the previous mode.

## Migration from v1.x

v1.x stored one global `AUTH_MODE`. On first start after upgrading, the tool
proposes: allowed = {old mode}, every user → old mode, with safe downgrades
for users whose enrollment is incomplete (e.g. a `password_totp` user without
a TOTP secret → `password`), each adjustment listed. Nothing is changed until
the administrator confirms; declining leaves the running v1 configuration
untouched (management features stay locked until migrated).

## Security properties

- No secrets in the policy file, the policy script, or their outputs.
- Passwords exist only as hashes in `/etc/shadow`; TOTP secrets root-only
  0400; the YubiCloud key only in root-only 0600 files.
- Every deny is logged with the CN and a fixed reason string — never with
  passwords, OTPs, secrets or API keys.
- Unknown certificate CN ⇒ deny. Missing/unreadable policy file ⇒ deny.
  Missing PAM plugin while credential modes are in use ⇒ OpenVPN refuses to
  start (visible failure) rather than skipping credential checks.
- Username↔CN equality is always enforced; credentials of user A can never
  be combined with the certificate of user B.
