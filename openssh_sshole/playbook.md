# OpenSSH "sshole" Password Bypass on musl / Alpine (CVE-2026-123158) — Detection & Response Playbook

> **Note for AI agents:** This playbook looks for a **vulnerable state**, not a one-time poisoned install. No exposure window applies: a container or host in the affected state can be logged into **now**. The bug lives in an **OS package inside container images** (Alpine's `openssh-server`), so manifest scanning won't find it. Search Dockerfiles, built images, deployment manifests and IaC instead. Adapt the discovery searches to wherever your org defines images (Dockerfiles, Helm charts, Kubernetes manifests, `docker-compose.yml`, Terraform/Packer). Adapt the log step to wherever your containers and hosts ship `sshd` logs. The detection logic is the same on any platform.

## Variables — Fill These In First

```bash
# Your GitHub organization name
export ORG="your-org-name"

# Public disclosure + fix release (OpenSSH 10.6p2, Alpine backports). Public PoCs exist from the same day.
# Before this date the bug was undisclosed. Review logs from as far back as you retain them.
export DISCLOSED="2026-11-05T00:00:00Z"

export LOG_DIR="/tmp/supply-chain-scan-openssh-sshole"
mkdir -p "$LOG_DIR"
```

---

## Background

**CVE-2026-123158** "sshole" (CVSS 3.1 **8.1**, `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`, CWE-394).

musl libc's `crypt()` returns the literal string `*` when hashing fails, rather than `NULL`. Its SHA-256/SHA-512 crypt fails on any password over 256 bytes. Since the 2016 user-enumeration fix (CVE-2016-6210), `sshd` hashes the submitted password even for accounts with no usable hash, using a "fake salt" copied from another account's `$5$`/`$6$` hash. On an `sshd` built **without PAM** against musl, a 257–1024 byte password therefore hashes to `*`, matches a stored `*`, and the login succeeds with no credentials.

Alpine's default `openssh-server` package is built without PAM. OpenSSH 10.6p2 adds a workaround in `sshd`, and Alpine backported it to every branch from 3.16 to edge.

### Affected / Fixed (Alpine `openssh`)

| Alpine branch | Fixed version |
|---|---|
| edge | `10.6_p2-r0` |
| 3.24 | `10.3_p1-r2` |
| 3.23 | `10.2_p1-r1` |
| 3.22 | `10.0_p1-r11` |
| 3.21 | `9.9_p2-r1` |
| 3.20 | `9.7_p1-r6` |
| 3.19 | `9.6_p1-r3` |
| 3.18 | `9.3_p2-r4` |
| 3.17 | `9.1_p1-r7` |
| 3.16 | `9.0_p1-r6` |
| **≤ 3.15** | **no fix will ship.** Disable password auth or move to a supported base. |

Outside Alpine: any OpenSSH **before 10.6p2** built against musl without PAM (OpenWrt, Buildroot, Yocto, custom static builds).

### Exploitation preconditions (ALL must be true)

1. `sshd` is linked against **musl** and runs **without PAM**: Alpine `openssh-server`, or `openssh-server-pam` with `UsePAM no`.
2. The installed `openssh` is older than the fixed version for its branch (table above).
3. `PasswordAuthentication yes`. This is the OpenSSH default; Alpine does not change it.
4. A **target account** has `*` as its effective password field and `sshd` would let it try a password. The effective field is the `/etc/shadow` entry, or the `/etc/passwd` field when the account has no shadow line. "Would let it try" means the account isn't expired, isn't excluded by `AllowUsers`/`DenyUsers`/`AllowGroups`/`DenyGroups`, and isn't switched to key-only by a `Match` block or `AuthenticationMethods`. `root` has been `*` on Alpine base images since 3.16, but the default `PermitRootLogin prohibit-password` protects it. Key-only service users, directory users, and the `alpine` user on Alpine cloud images 3.18.11–3.24.3 (passwordless `doas` → root) are the realistic targets.
5. At least one **other** local account has a real `$5$` / `$6$` hash. This is typically set by `chpasswd` in a Dockerfile or entrypoint.
6. The attacker can reach the SSH port.

### What IS affected

- Container images `FROM alpine` (or another musl base) that install `openssh-server` and run `sshd`, typically SSH build agents, bastion/jump containers, SFTP endpoints, dev containers and test fixtures, **and** set a password for some account.
- Alpine VMs and cloud images (AMI / VHD / qcow2) **3.18.11 through 3.24.3** with password auth enabled. Images built from 3.21.10, 3.22.8, 3.23.8, 3.24.4 and later ship `PasswordAuthentication no`.
- musl-based embedded builds (OpenWrt / Buildroot / Yocto) running OpenSSH before 10.6p2 without PAM.

### What is NOT affected

- **glibc** images and hosts (Debian, Ubuntu, Fedora, RHEL, UBI, distroless-glibc), even with many `*` accounts in `/etc/shadow`. glibc `crypt()` returns `NULL` on failure.
- Alpine images that install only the **client** (`openssh-client`, `openssh-client-default`, `openssh-keygen`), or install `openssh-server` but never start `sshd`. Common case: `apk add openssh` for `git` over SSH in CI.
- `sshd` with `UsePAM yes` (`openssh-server-pam`).
- `PasswordAuthentication no` (key-only), **as long as** nothing re-enables it: no startup flag `-o PasswordAuthentication=yes`, no alternate `-f` config, and no `Match` block setting it back to `yes` for some addresses, ports or users.
- Accounts locked with `!` (Alpine root before 3.16, `passwd -l` users). Only an exact `*` matches.
- `root` when `PermitRootLogin` is anything other than `yes`.
- Images with **no** `$5$`/`$6$` hash anywhere. With no real hash to borrow a salt from, the fake salt falls back to DES, which never returns `*`. A yescrypt (`$y$`) hash copied in from a glibc distro did **not** act as a donor in testing.
- `*` accounts that are expired, excluded by `AllowUsers`/`DenyUsers`/`AllowGroups`/`DenyGroups`, or forced to key-only by a `Match` block or `AuthenticationMethods publickey` (all lab-verified as not exploitable).

### Lock-file / pinning note

Nothing in an application lock file covers this. The vulnerable code is the OS package, so it's governed by the **base image tag/digest and the `apk add` at build time**. A Dockerfile pinned to `alpine:3.22` with `apk add openssh-server` picks up the fix **only when the image is rebuilt**. An image built yesterday still carries `10.0_p1-r10`. A digest-pinned base (`alpine@sha256:...`) plus a `--no-cache` layer still resolves the *current* branch package at build time. What matters is the date of the last build, not the Dockerfile text.

---

## Phase 1 — Discover SSH-Server Images & Hosts Across the Org

**Positive control first:** confirm search reaches your code. Run `gh search code "FROM alpine" --owner "$ORG" -L 5` and check that it returns Dockerfiles you know exist. A zero-hit search and a broken search look identical.

```bash
# Dockerfiles / scripts that install or run an SSH server, or set passwords.
# Sleep between queries: code search allows ~10 requests/minute.
for q in "openssh-server" "apk add openssh" "/usr/sbin/sshd" "sshd -D" "chpasswd" "PasswordAuthentication"; do
  echo "=== $q ==="
  gh search code "$q" --owner "$ORG" --json repository,path -L 100 2>/dev/null | \
    python3 -c "import json,sys; [print(i['repository']['nameWithOwner'],'|',i['path']) for i in json.load(sys.stdin)]" | sort -u
  sleep 7
done | tee "$LOG_DIR/discovery-dockerfiles.txt"

# Third-party SSH/SFTP images referenced in deployment definitions (all Alpine-based or with Alpine variants)
for q in "linuxserver/openssh-server" "atmoz/sftp" "jenkins/ssh-agent" "panubo/sshd" "gitea/gitea" "gogs/gogs"; do
  echo "=== $q ==="
  gh search code "$q" --owner "$ORG" --json repository,path -L 100 2>/dev/null | \
    python3 -c "import json,sys; [print(i['repository']['nameWithOwner'],'|',i['path']) for i in json.load(sys.stdin)]" | sort -u
  sleep 7
done | tee "$LOG_DIR/discovery-thirdparty.txt"

# Alpine VMs / cloud images in IaC (AMI name filters, Packer sources)
for q in "alpine-3" "tiny-cloud" "alpine-cloud-images"; do
  echo "=== $q ==="
  gh search code "$q" --owner "$ORG" --json repository,path -L 100 2>/dev/null | \
    python3 -c "import json,sys; [print(i['repository']['nameWithOwner'],'|',i['path']) for i in json.load(sys.stdin)]" | sort -u
  sleep 7
done | tee "$LOG_DIR/discovery-vms.txt"
```

Classify each hit:

- **Dockerfile** that installs `openssh-server` (or `openssh`, which pulls in the server on Alpine) **and** whose base is Alpine/musl → candidate. Open the file and note the `FROM` line, whether `sshd` is the entrypoint or started by a script, and any `chpasswd` / `echo user:pass` / `passwd` calls.
- **Dockerfile** that installs only `openssh-client` / `openssh-keygen` → not affected. Record it and move on.
- **Deployment manifest** (Helm `values.yaml`, k8s YAML, `docker-compose.yml`) referencing a third-party SSH image → candidate. Note the tag and env vars such as `PASSWORD_ACCESS=true` (linuxserver) or `user:pass` args (atmoz/sftp).
- **Terraform / Packer** referencing Alpine images → candidate VM. Check it in Phase 2c.
- Docs, READMEs and test snippets → note, but they aren't deployments.

Then list the **built image references** for each candidate: the registry path your CI pushes to (`ghcr.io/$ORG/...`, ECR, Artifact Registry) and the tags currently deployed. Phase 2 runs against the built images, not the Dockerfiles.

---

## Phase 2 — Determine the Vulnerable State

All of Phase 2 uses one script, `sshole-check.sh`. It runs **inside** the target (a throwaway container from an image, or an `exec` into a running container or VM) as root, and prints one `verdict=` line per `sshd` it finds. It never starts `sshd` or opens a port.

What it checks, per `sshd`:

- **Which `sshd`.** In a running container it uses the live `sshd` process: its real binary (`/proc/<pid>/exe`), plus the `-f` and `-o` flags it was started with. It reads the flags from argv, or from the `[listener]` process title that OpenSSH writes over argv. When `sshd` runs as a non-root user, only that user counts as a target, because a non-root `sshd` can only authenticate the account it runs as. For an image it uses the image's `ENTRYPOINT`/`CMD` when that starts `sshd`. Otherwise it checks every `sshd` / `sshd.pam` binary on disk with its default config. It finds unpackaged builds in `/usr/local` too.
- **Vulnerable build.** The binary is linked against musl. For an apk-owned binary, the package version is below the fixed version for its Alpine branch. For an unpackaged build, the embedded `OpenSSH_x.yPz` string is older than 10.6p2.
- **Per-account reachability.** It runs `sshd -T -C user=<account>,host=<addr>,addr=<addr>,lport=<port>` with the same flags as the real daemon, so `Match` blocks apply. It tries each test client address (one public, `10.0.0.1`, `172.16.0.1`, `192.168.0.1`, `100.64.0.1`, then loopback) on every port `sshd` listens on. It then requires `passwordauthentication yes`, no PAM, an `authenticationmethods` that allows plain `password`, `permitrootlogin yes` for root, and that `AllowUsers`/`DenyUsers`/`AllowGroups`/`DenyGroups` admit the account.
- **Targets and donors.** A target is an account whose effective password field is exactly `*`: the `/etc/shadow` entry, or the `/etc/passwd` field when there is no shadow line. Expired accounts are excluded. A donor is any account with a `$5$`/`$6$` hash.

```bash
cat > "$LOG_DIR/sshole-check.sh" <<'SSHOLE_CHECK'
#!/bin/sh
# sshole (CVE-2026-123158) exposure check. Runs INSIDE the target (image or running container), as root.
#   image:     docker run --rm -i --user 0 --entrypoint /bin/sh -e SSHD_CMDLINE="<image entrypoint+cmd>" <image> -s < sshole-check.sh
#   container: docker exec -i --user 0 <container> sh -s < sshole-check.sh
#   k8s:       kubectl exec -i -n <ns> <pod> -- sh -s < sshole-check.sh
# One line per sshd: verdict=<...> plus the facts behind it.

FIXED_TABLE="3.24:10.3_p1-r2 3.23:10.2_p1-r1 3.22:10.0_p1-r11 3.21:9.9_p2-r1 3.20:9.7_p1-r6 3.19:9.6_p1-r3 3.18:9.3_p2-r4 3.17:9.1_p1-r7 3.16:9.0_p1-r6"
REL=$(cut -d. -f1,2 /etc/alpine-release 2>/dev/null)
TODAY=$(( $(date +%s) / 86400 ))
TMPK=/tmp/.sshole_hostkey
# Client addresses to evaluate Match blocks against: a public one plus the private/CGNAT ranges an
# internal attacker would come from. Loopback is tracked separately (local-only exposure).
NET_ADDRS="203.0.113.10 10.0.0.1 172.16.0.1 192.168.0.1 100.64.0.1"
LOCAL_ADDRS="127.0.0.1 ::1"

ver_lt() {  # ver_lt A B -> true if upstream version A < B (e.g. 10.0p1 < 10.6p2)
  awk -v a="$1" -v b="$2" 'BEGIN{
    gsub(/p/,".",a); gsub(/p/,".",b); na=split(a,x,"."); nb=split(b,y,".");
    for(i=1;i<=(na>nb?na:nb);i++){ if((x[i]+0)<(y[i]+0)) exit 0; if((x[i]+0)>(y[i]+0)) exit 1 } exit 1 }'
}

pkg_status() {  # pkg_status <binary> -> "<owner> <version> <VULNERABLE|VULNERABLE_NO_FIX|fixed|unknown>"
  b=$1; owner=""
  command -v apk >/dev/null 2>&1 && owner=$(apk info -W "$b" 2>/dev/null | sed -n 's/.* is owned by //p' | head -1)
  case "$owner" in
    openssh-server-*)
      v=${owner#openssh-server-}; v=${v#pam-}
      fix=""; for kv in $FIXED_TABLE; do [ "${kv%%:*}" = "$REL" ] && fix=${kv#*:}; done
      case "$REL" in 3.[0-9]|3.1[0-5]) echo "$owner $v VULNERABLE_NO_FIX"; return ;; esac
      [ -z "$fix" ] && fix=10.6_p2-r0
      if [ "$(apk version -t "$v" "$fix")" = "<" ]; then echo "$owner $v VULNERABLE"; else echo "$owner $v fixed"; fi ;;
    *)
      v=$(grep -ao 'OpenSSH_[0-9][0-9.]*p[0-9]*' "$b" 2>/dev/null | head -1); v=${v#OpenSSH_}
      if [ -z "$v" ]; then echo "unpackaged unknown unknown"
      elif ver_lt "$v" 10.6p2; then echo "unpackaged $v VULNERABLE"; else echo "unpackaged $v fixed"; fi ;;
  esac
}

account_field() {  # effective password field: /etc/shadow entry if present, else the /etc/passwd field
  if grep -q "^$1:" /etc/shadow 2>/dev/null; then
    awk -F: -v u="$1" '$1==u{print $2; exit}' /etc/shadow
  else
    awk -F: -v u="$1" '$1==u{print $2; exit}' /etc/passwd
  fi
}

expired() {  # shadow expire field (8) in the past
  e=$(awk -F: -v u="$1" '$1==u{print $8}' /etc/shadow 2>/dev/null)
  [ -n "$e" ] && [ "$e" -lt "$TODAY" ] 2>/dev/null
}

matches_any() {  # matches_any <word> <glob list...>
  w=$1; shift
  for p in "$@"; do p=${p%%@*}; case "$w" in $p) return 0 ;; esac; done
  return 1
}

sshd_T() {  # sshd_T <binary> [-C spec] -> sshd -T output with the daemon's own -f/-o flags
  b=$1; shift
  out=$(eval "\"$b\" -T $ARGS $HK" '"$@"' 2>/dev/null)
  if [ -z "$out" ] && [ -z "$HK" ]; then
    [ -f "$TMPK" ] || ssh-keygen -q -t ed25519 -N '' -f "$TMPK" >/dev/null 2>&1 || "$(dirname "$b")/../bin/ssh-keygen" -q -t ed25519 -N '' -f "$TMPK" >/dev/null 2>&1
    HK="-h $TMPK"
    out=$(eval "\"$b\" -T $ARGS $HK" '"$@"' 2>/dev/null)
  fi
  printf '%s\n' "$out"
}

cfg_allows() {  # cfg_allows <user> <sshd -T output> -> 0 if that effective config lets <user> try a password
  c=$2
  val() { printf '%s\n' "$c" | awk -v k="$1" '$1==k{$1=""; sub(/^ /,""); print}'; }
  [ "$(val passwordauthentication)" = yes ] || return 1
  [ "$(val usepam)" = yes ] && return 1
  am=$(val authenticationmethods)
  if [ -n "$am" ] && [ "$am" != any ]; then
    ok=1; for m in $am; do [ "$m" = password ] && ok=0; done; [ $ok = 0 ] || return 1
  fi
  if [ "$1" = root ]; then [ "$(val permitrootlogin)" = yes ] || return 1; fi
  au=$(val allowusers | tr '\n' ' '); du=$(val denyusers | tr '\n' ' ')
  ag=$(val allowgroups | tr '\n' ' '); dg=$(val denygroups | tr '\n' ' ')
  groups=$(id -Gn "$1" 2>/dev/null)
  [ -n "$du" ] && matches_any "$1" $du && return 1
  [ -n "$au" ] && ! matches_any "$1" $au && return 1
  if [ -n "$dg" ]; then for g in $groups; do matches_any "$g" $dg && return 1; done; fi
  if [ -n "$ag" ]; then hit=1; for g in $groups; do matches_any "$g" $ag && hit=0; done; [ $hit = 0 ] || return 1; fi
  return 0
}

user_reach() {  # user_reach <binary> <user> -> prints "net <addr>:<port>", "local <addr>:<port>" or nothing
  for set in net local; do
    if [ $set = net ]; then addrs=$NET_ADDRS; else addrs=$LOCAL_ADDRS; fi
    for a in $addrs; do
      for pt in $PORTS; do
        # host=<addr> mirrors the default UseDNS no, where Match Host sees the client address
        if cfg_allows "$2" "$(sshd_T "$1" -C "user=$2,host=$a,addr=$a,laddr=0.0.0.0,lport=$pt")"; then echo "$set $a:$pt"; return; fi
      done
    done
  done
}

pw_match_blocks() {  # count Match blocks that set PasswordAuthentication yes, across the config and its Includes
  main=$(printf '%s\n' "$ARGS" | sed -n "s/.*-f '\([^']*\)'.*/\1/p")
  [ -n "$main" ] || main=$(grep -ao '/[A-Za-z0-9_./-]*/sshd_config' "$1" 2>/dev/null | head -1)
  [ -f "$main" ] || { echo 0; return; }
  files=$main
  for g in $(awk 'tolower($1)=="include"{for(i=2;i<=NF;i++) print $i}' "$main"); do
    case "$g" in /*) ;; *) g="$(dirname "$main")/$g" ;; esac
    for f in $g; do [ -f "$f" ] && files="$files $f"; done
  done
  awk 'tolower($1)=="match"{m=1; next} m && tolower($1)=="passwordauthentication" && tolower($2)=="yes"{n++} END{print n+0}' $files
}

parse_args() {  # sshd argv (one per line on stdin) -> ARGS with only -f / -o kept, shell-quoted
  ARGS=""; nxt=""
  while IFS= read -r a; do
    if [ -n "$nxt" ]; then ARGS="$ARGS $nxt '$a'"; nxt=""; continue; fi
    case "$a" in
      -f|-o) nxt=$a ;;
      -f?*|-o?*) ARGS="$ARGS ${a%"${a#??}"} '${a#??}'" ;;
    esac
  done
}

check_sshd() {  # check_sshd <binary> <mode>
  bin=$1; mode=$2; HK=""
  libc=glibc; { grep -q musl "$bin" || grep -aq musl "$bin"; } 2>/dev/null && libc=musl
  set -- $(pkg_status "$bin"); owner=$1; ver=$2; vs=$3
  # a -C spec is required as soon as the config has any Match block keyed on lport/laddr
  PORTS=$(sshd_T "$bin" -C "user=root,host=203.0.113.10,addr=203.0.113.10,laddr=0.0.0.0,lport=22" | awk '$1=="port"{print $2}' | sort -u | tr '\n' ' ')
  [ -n "$PORTS" ] || PORTS=22
  targets=""; local_targets=""; donors=""; via=""
  for u in $(cut -d: -f1 /etc/passwd); do
    f=$(account_field "$u")
    [ -n "$RUN_USER" ] && [ "$u" != "$RUN_USER" ] && case "$f" in '*') continue ;; esac
    case "$f" in
      '*')
        expired "$u" && continue
        r=$(user_reach "$bin" "$u")
        case "$r" in
          net*)   targets="$targets $u"; [ -n "$via" ] || via=${r#net } ;;
          local*) local_targets="$local_targets $u" ;;
        esac ;;
      '$5$'*|'$6$'*) donors="$donors $u" ;;
    esac
  done
  v=NOT_EXPOSED
  case "$vs" in VULNERABLE*)
    if [ "$libc" = musl ]; then
      if [ -n "$donors" ] && [ -n "$targets" ]; then v=EXPOSED
      elif [ -n "$donors" ] && [ -n "$local_targets" ]; then v=EXPOSED_LOCAL_ONLY
      else v=VULNERABLE_PACKAGE_ONLY; fi
    fi ;;
  esac
  [ "$mode" = image-default ] && [ "$v" = EXPOSED ] && v=EXPOSED_IF_SSHD_STARTED
  echo "verdict=$v mode=$mode sshd=$bin args=[${ARGS# }]${RUN_USER:+ runs_as=$RUN_USER} libc=$libc alpine=${REL:-none} owner=$owner version=$ver status=$vs ports=[${PORTS% }] targets=[${targets# }]${via:+ via=$via} local_only_targets=[${local_targets# }] donors=[${donors# }] pw_match_blocks=$(pw_match_blocks "$bin")"
}

found=0; SEEN=""; RUN_USER=""
for p in /proc/[0-9]*; do
  [ -r "$p/cmdline" ] || continue
  n=$(tr '\0' '\n' < "$p/cmdline" 2>/dev/null | grep -c .)
  if [ "$n" -gt 1 ]; then
    words=$(tr '\0' '\n' < "$p/cmdline")                         # untouched argv
  else
    t=$(tr -d '\0' < "$p/cmdline" 2>/dev/null)                   # proctitle, e.g. "sshd: /usr/sbin/sshd -D -o X [listener] 0 of 10-100 startups"
    case "$t" in *"[listener]"*) ;; *) continue ;; esac           # per-connection children ("sshd: user [priv]") are skipped
    t=${t#*: }; t=${t%%\[listener\]*}                        # title prefix is "sshd: " or "sshd.pam: "
    words=$(printf '%s\n' $t)
  fi
  # /proc/<pid>/exe is unreadable for another uid without CAP_SYS_PTRACE, so fall back to argv[0]
  bin=$(readlink "$p/exe" 2>/dev/null) || bin=$(printf '%s\n' "$words" | head -1)
  case "$bin" in /*) ;; *) bin=$(command -v "$bin" 2>/dev/null) ;; esac
  case "$(basename "$bin" 2>/dev/null)" in sshd|sshd.pam) ;; *) continue ;; esac
  argv=$(printf '%s\n' "$words" | tail -n +2)
  # a non-root sshd can only authenticate the account it runs as
  RUN_USER=""; ruid=$(awk '/^Uid:/{print $2}' "$p/status" 2>/dev/null)
  [ -n "$ruid" ] && [ "$ruid" != 0 ] && RUN_USER=$(awk -F: -v i="$ruid" '$3==i{print $1; exit}' /etc/passwd)
  key="$bin|$argv"
  case "$SEEN" in *"<$key>"*) continue ;; esac
  SEEN="$SEEN<$key>"
  parse_args <<EOF
$argv
EOF
  check_sshd "$bin" runtime; found=1
done

if [ $found = 0 ] && [ -n "$SSHD_CMDLINE" ] && printf '%s' "$SSHD_CMDLINE" | grep -q 'sshd'; then
  bin=$(printf '%s\n' $SSHD_CMDLINE | grep -m1 'sshd')
  case "$bin" in /*) ;; *) bin=$(command -v "$bin") ;; esac
  if [ -x "$bin" ]; then
    parse_args <<EOF
$(printf '%s\n' $SSHD_CMDLINE | sed -n "\|^$bin\$|,\$p" | tail -n +2)
EOF
    check_sshd "$bin" image-cmd; found=1
  fi
fi

if [ $found = 0 ]; then
  ARGS=""
  for bin in $(find / -xdev \( -path /proc -o -path /sys \) -prune -o -type f \( -name sshd -o -name sshd.pam \) -perm -u+x -print 2>/dev/null); do
    check_sshd "$bin" image-default; found=1
  done
fi

[ $found = 0 ] && echo "verdict=NOT_EXPOSED mode=none sshd=none alpine=${REL:-none}"
rm -f "$TMPK" "$TMPK.pub"
SSHOLE_CHECK
```

### 2a. Inspect each built image

```bash
# One image ref per line in images.txt. Passes the image's own ENTRYPOINT+CMD so -f/-o flags are honoured.
while read -r img; do
  docker pull -q "$img" >/dev/null
  cmd=$(docker image inspect -f '{{join .Config.Entrypoint " "}} {{join .Config.Cmd " "}}' "$img")
  docker run --rm -i --user 0 --entrypoint /bin/sh -e SSHD_CMDLINE="$cmd" "$img" -s < "$LOG_DIR/sshole-check.sh" 2>/dev/null |
    sed "s|^|$img\t|"
done < "$LOG_DIR/images.txt" | tee "$LOG_DIR/image-verdicts.tsv"
```

### 2b. Check running containers (authoritative)

The image check can't see what happens at start-up: entrypoints that add users or set passwords, `sshd` flags injected by an init system, or config rendered from env vars. For every **running** workload from a candidate image, run the same script against the live container:

```bash
# Kubernetes: the exec user must be able to read /etc/shadow (root). Add -c <container> for multi-container pods.
kubectl exec -i -n <ns> <pod> -- sh -s < "$LOG_DIR/sshole-check.sh"
# Plain Docker
docker exec -i --user 0 <container> sh -s < "$LOG_DIR/sshole-check.sh"
```

How to read the verdicts:

| `verdict` | Meaning | Action |
|---|---|---|
| `EXPOSED` (`mode=runtime`) | A live `sshd` is vulnerable and at least one `*` account is reachable with a password while a `$5$/$6$` donor exists | Exploitable now if the port is reachable. Go to Phase 3 immediately, then rebuild. |
| `EXPOSED` (`mode=image-cmd`) | The image's own start command would run an exploitable `sshd` | Find every running workload from this image and run 2b. Rebuild. |
| `EXPOSED_IF_SSHD_STARTED` (`mode=image-default`) | Exploitable state on disk, but nothing in the image command starts `sshd` (or an init system such as s6/supervisord starts it) | Run 2b on running workloads; it settles whether `sshd` actually runs. Rebuild. |
| `EXPOSED_LOCAL_ONLY` | Password auth for a `*` account is enabled only for loopback clients (e.g. `Match Address 127.0.0.1`) | Not reachable from the network, but any foothold inside the container or host can use it to switch accounts. Rebuild; fix the `Match` block. |
| `VULNERABLE_PACKAGE_ONLY` | Vulnerable musl `sshd`, but no reachable `*` target or no donor in this state | Rebuild. If seen in image mode, also run 2b, because start-up scripts can create the missing piece. If `pw_match_blocks` is above 0, review those `Match` blocks by hand (see below). |
| `NOT_EXPOSED` | glibc, no `sshd`, or a fixed version | No action for this CVE. |

`targets=[...]` lists the accounts a bypass would log in as, and `via=<addr>:<port>` the first test client address and listening port that reached them. `donors=[...]` lists the accounts supplying the salt. Record all three in the evidence table.

`pw_match_blocks=N` counts `Match` blocks, in the config and its `Include`d files, that set `PasswordAuthentication yes`. The script tests a public address, the RFC 1918 and CGNAT ranges, and loopback, on every port `sshd` listens on. It does **not** test `Match Host` patterns that need reverse DNS, `Match LocalAddress`, or exotic address ranges. So when the verdict is not `EXPOSED` but `pw_match_blocks` is above 0, read each block's condition. If an attacker could satisfy it, treat the `sshd` as exposed.

### 2c. Alpine VMs and cloud images

Run the same script on each Alpine VM (including instances launched from Alpine AMIs/VHDs 3.18.11–3.24.3), as root:

```bash
ssh <vm> 'sudo sh -s' < "$LOG_DIR/sshole-check.sh"     # use doas instead of sudo on stock Alpine
```

`targets=[alpine]` on a vulnerable VM is the high-impact case. That user has passwordless `doas`, so a bypass is a root shell.

### 2d. Find what was built and when (CI build logs)

Images are only as fresh as their last build. To find which images pulled a vulnerable `openssh-server`, grep CI build logs for the apk **install line**. Match install lines only, not the Dockerfile text:

```bash
# After downloading build logs for the candidate repos into $LOG_DIR/ci-logs/
grep -rhoE "Installing openssh-server(-pam)? \([0-9][0-9._a-z-]*\)" "$LOG_DIR/ci-logs/" | sort | uniq -c
```

Compare each version with the fixed table. Note: `apk add -q` and `--quiet` builds don't print install lines. If you get no hits, run 2a on the pushed image instead.

---

## Phase 3 — Check Exposure & Review Logs for Exploitation

### 3a. Is the SSH port reachable?

For every `EXPOSED` image or container, determine who can reach port 22 (or the mapped port): a Kubernetes `Service` of type `LoadBalancer`/`NodePort`, `hostPort`, docker `-p`, security groups or ingress rules. This lives on the cluster or network, outside repo scanning, so have the deployment owner confirm. Internal-only exposure still matters: any compromised workload in the same network can exploit it.

### 3b. Review `sshd` logs for the bypass signature

The exploit shows a distinctive pattern, **validated in a lab against Alpine 3.15 / OpenSSH 8.8p1**. A public PoC primes the fake salt with one failed attempt, then sends the oversized password **on the same connection (same source port)**:

```
Failed password for <user> from <ip> port <port> ssh2
Accepted password for <user> from <ip> port <port> ssh2
```

where `<user>`'s effective password field is `*`: the `/etc/shadow` entry, or the `/etc/passwd` field when there is no shadow line. A key-only account should **never** produce `Accepted password`.

```bash
# Alpine hosts (syslog) / containers logging to stderr
grep -h "Accepted password for" /var/log/messages* 2>/dev/null
kubectl logs -n <ns> <pod> --since=720h 2>/dev/null | grep "Accepted password for"
docker logs <container> 2>&1 | grep "Accepted password for"

# For each hit, check the user's effective password field (shadow entry, else the /etc/passwd field)
for u in $(grep -hoE "Accepted password for [^ ]+" /var/log/messages* 2>/dev/null | awk '{print $4}' | sort -u); do
  if grep -q "^$u:" /etc/shadow; then f=$(awk -F: -v u="$u" '$1==u{print $2}' /etc/shadow)
  else f=$(awk -F: -v u="$u" '$1==u{print $2}' /etc/passwd); fi
  [ "$f" = "*" ] && echo "$u  STAR_ACCOUNT -> LIKELY EXPLOITED" || echo "$u  has a real password"
done
```

Also look in your log platform for `Accepted password` from **unexpected source IPs** on any musl `sshd`, and for bursts of `Failed password` immediately followed by `Accepted password` on the same `port`.

### 3c. If exploitation is likely

Treat the container or host as compromised. Capture `/root/.ssh/authorized_keys`, `/home/*/.ssh/authorized_keys`, crontabs, `/etc/doas.conf`, `/etc/passwd`, `/etc/shadow`, and the process list before you destroy it. Then rotate every credential reachable from it (Phase 4, step 5).

---

## Phase 4 — Remediation & Hardening

1. **Rebuild every affected image** on a current Alpine patch release, so the build resolves the fixed `openssh` for its branch: `docker build --pull --no-cache ...`. Redeploy and confirm with 2a. Upgrading in place and restarting (`apk upgrade -U -a && rc-service sshd restart`) is a stop-gap for long-lived containers and VMs. Upgrading the package alone does **not** replace a running `sshd`.
2. **Alpine ≤ 3.15**: no fixed package exists. Move to a supported base, or apply step 3 permanently.
3. **Turn password auth off** unless it is genuinely required:
   ```
   # /etc/ssh/sshd_config.d/00-no-passwords.conf   (Alpine 3.19+ reads this directory)
   PasswordAuthentication no
   KbdInteractiveAuthentication no
   ```
   Then run `sshd -t && rc-service sshd restart` (or rebuild). Keep a session open and test a key login before closing it.

   **Verify with `sshole-check.sh` against the running container or host, not with `sshd -T | grep passwordauthentication`.** In the lab, three setups printed `passwordauthentication no` there and were still exploitable:
   - `sshd` was started with `-o PasswordAuthentication=yes`, or with `-f` pointing at a different config file. Command-line flags beat the config file.
   - A `Match Address 10.0.0.0/8,...` or `Match LocalPort 2222` block set `PasswordAuthentication yes` after the drop-in. Plain `sshd -T` shows only the settings for a connection that matches no `Match` block.

   Also check that the drop-in is read at all. Alpine's default `sshd_config` has `Include /etc/ssh/sshd_config.d/*.conf` at the top, but some images comment it out or ship their own config (linuxserver does both). Images that render `sshd_config` at start-up need their own setting: on linuxserver, set `PASSWORD_ACCESS=false`, because the init script rewrites `PasswordAuthentication` from that variable on every start.
4. **Stop baking passwords into images**: remove `chpasswd` / `echo user:pass | chpasswd` / `passwd` steps from Dockerfiles and entrypoints. For third-party images, switch to key auth (linuxserver: `PASSWORD_ACCESS=false` with `PUBLIC_KEY`; atmoz/sftp: mount keys instead of `user:pass`). Lock unused accounts with `!` (`passwd -l`), not `*`.
5. **If Phase 3 found a likely bypass, rotate everything reachable from that container or host**: CI/CD secrets mounted or injected into it, deploy keys and `authorized_keys`, registry credentials, cloud credentials and instance-role sessions, and any secrets in its environment or volumes. Then review its outbound connections and changes since `$DISCLOSED`.
6. **Don't expose `sshd` in containers at all** where you can avoid it. Use `kubectl exec` / `docker exec`, SSM Session Manager, or a hardened glibc bastion.

---

## Evidence Table

Write one row per image or host to `$LOG_DIR/evidence-repos.csv`:

| Field | Value |
|---|---|
| Repo / Dockerfile or deployment source | |
| Image ref / digest (or VM id) | |
| libc / Alpine branch | |
| `sshd` binary + start flags (`sshd=` / `args=`) | |
| `openssh` version → fixed version (`version=` / `status=`) | |
| Reachable `*` targets (`targets=`) | |
| `$5$`/`$6$` donors (`donors=`) | |
| Image verdict (2a) / runtime verdict (2b) | EXPOSED / EXPOSED_IF_SSHD_STARTED / VULNERABLE_PACKAGE_ONLY / NOT_EXPOSED |
| Port reachable from | internet / VPC / cluster-internal / none |
| `Accepted password` for a `*` account in logs? | yes (list) / no |
| Rebuilt + redeployed? | yes / no |
| Secrets rotated? | yes / no / n/a |

---

## Pitfalls & Fixes

These come from a 26-case lab run. Each case was a Docker container checked against the live two-step bypass; the cases include real `jenkins/ssh-agent:alpine3.24` and `linuxserver/openssh-server` images.

- **Read the running daemon, not the default config.** `sshd` started with `-o PasswordAuthentication=yes` or `-f /path/custom_config` was exploitable while `/etc/ssh/sshd_config` said `no`. The script takes `-f`/`-o` from the live process (or the image `CMD`) and passes them to `sshd -T`.
- **`PasswordAuthentication no` can be silently undone, and plain `sshd -T` hides it.** Alpine's recommended drop-in (`00-no-passwords.conf`) blocked the bypass on its own. But with a later `Match Address 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16` or `Match LocalPort 2222` block setting it back to `yes`, the bypass worked from an internal address or on that port, while `sshd -T` still printed `passwordauthentication no`. The script evaluates every test address and listening port and reports `pw_match_blocks`.
- **Evaluate per account, not globally.** `Match User svc` + `PasswordAuthentication no`, `AllowUsers`, `AuthenticationMethods publickey`, and an expired account all left a global `sshd -T` saying "exposed" when the bypass failed. The script runs `sshd -T -C user=<account>` and applies those rules per target.
- **`*` can live in `/etc/passwd`.** An account with `*` in its passwd field and **no** shadow line was bypassed, because `sshd` falls back to the passwd field. Grepping `/etc/shadow` alone misses it, in both the state check and the log check.
- **Not every `sshd` comes from apk.** A from-source OpenSSH in `/usr/local/sbin` was exploitable and invisible to `apk info`. The script finds the binary from the process or disk, decides musl from the binary, and reads its embedded `OpenSSH_x.yPz` version.
- **An installed `sshd` isn't a running `sshd`.** An image with an exploitable state whose `CMD` never starts `sshd` is reported as `EXPOSED_IF_SSHD_STARTED`, not `EXPOSED`. The runtime check (2b) settles it.
- **Start-up scripts change the answer.** A donor password set by the entrypoint is `VULNERABLE_PACKAGE_ONLY` in the image and `EXPOSED` at runtime. Always run 2b on running workloads.
- **`apk add openssh` is not `openssh-client`.** On Alpine, the `openssh` meta-package pulls in `openssh-server`. Treat it as a server install, then check whether `sshd` is ever started.
- **glibc images are full of `*` accounts.** `debian:bookworm-slim` has 17 of them (`daemon`, `bin`, `www-data`, ...). They are irrelevant without musl. The script gates on the binary's libc. Don't hand-grep `/etc/shadow` and flag glibc images.
- **`UsePAM` missing from `sshd -T` means no PAM.** Alpine's non-PAM build doesn't recognise the keyword. `sshd.pam` (the `openssh-server-pam` binary) is checked too.
- **`sshd -T` fails without host keys** in a never-started image. The script retries with a throwaway key in `/tmp` and removes it afterwards.
- **`root:*` alone is not exposure on default config.** Alpine ≥ 3.16 base images all have `root:*`, but `PermitRootLogin prohibit-password` blocks it. Root counts as a target only when the effective `permitrootlogin` is `yes`.
- **A single long-password attempt can fail even on a vulnerable server.** A fresh connection with only the 300-byte password was rejected. The bypass needed a prior failed attempt on the **same connection** to prime `sshd`'s cached fake salt (this matches the public PoC). Don't "verify" exposure with a one-shot login. Trust the state check, and if you must test, do it only on an isolated copy.
- **Pinned Dockerfile, stale image.** `FROM alpine:3.22` in the repo says nothing about the `openssh` revision in the image deployed last week. Inspect the pushed image or its digest, not the Dockerfile.
- **Container scanners may not flag it yet.** Alpine's secdb entry for the fix lagged the advisory, so Trivy/Grype-style scanners that key on secdb may show no CVE on vulnerable images for a while. Use the script's version check.
