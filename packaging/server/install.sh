#!/usr/bin/env bash
# Install or upgrade vykey-server from the latest GitHub release on Debian,
# Ubuntu, CentOS Stream, RHEL, Rocky, Alma or Fedora, and run it as a
# systemd service listening on 127.0.0.1:8470.
#
#   curl -fsSL https://raw.githubusercontent.com/vykey/vykey/main/packaging/server/install.sh | sudo bash
#   curl -fsSL .../install.sh | sudo bash -s -- --nginx
#
# Options:
#   --nginx            also install nginx and proxy a domain to the server,
#                      with a Let's Encrypt certificate if wanted (asks)
#   --domain NAME      domain for --nginx (otherwise asked)
#   --email ADDR       Let's Encrypt contact for --nginx (otherwise asked)
#   --version X.Y.Z    install this release instead of the latest
#
# Running it again upgrades the binary and restarts the service; an existing
# systemd unit or nginx config is left as it is.
set -euo pipefail

REPO=vykey/vykey
BIN=/usr/local/bin/vykey-server
UNIT=/etc/systemd/system/vykey-server.service
LISTEN=127.0.0.1:8470

with_nginx=0
domain=
email=
version=

say()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage: install.sh [--nginx] [--domain NAME] [--email ADDR] [--version X.Y.Z]

Installs or upgrades vykey-server and runs it as a systemd service on
127.0.0.1:8470. With --nginx, also sets up nginx (and Let's Encrypt) for
a domain in front of it.
EOF
  exit "${1:-0}"
}

while [ $# -gt 0 ]; do
  case $1 in
    --nginx) with_nginx=1 ;;
    --domain) domain=${2:?--domain needs a value}; shift ;;
    --domain=*) domain=${1#*=} ;;
    --email) email=${2:?--email needs a value}; shift ;;
    --email=*) email=${1#*=} ;;
    --version) version=${2:?--version needs a value}; shift ;;
    --version=*) version=${1#*=} ;;
    -h|--help) usage ;;
    *) warn "unknown option: $1"; usage 1 ;;
  esac
  shift
done

# Prompts read from the terminal, so they work under `curl ... | bash` too.
ask() { # ask VAR "question" [default]
  local answer
  if [ -r /dev/tty ]; then
    read -r -p "$2${3:+ [$3]}: " answer </dev/tty || true
  fi
  printf -v "$1" '%s' "${answer:-${3:-}}"
}

# --- checks -----------------------------------------------------------------

[ "$(id -u)" = 0 ] || die "run as root (sudo)"

command -v systemctl >/dev/null && [ -d /run/systemd/system ] \
  || die "systemd is required"
# DynamicUser= and StateDirectory= in the unit need systemd 235+.
systemd_version=$(systemctl --version | awk 'NR==1 {print $2}')
[ "${systemd_version%%.*}" -ge 235 ] 2>/dev/null \
  || die "systemd $systemd_version is too old (235+ needed; CentOS 7 is not supported)"

[ -r /etc/os-release ] || die "/etc/os-release not found: unknown distribution"
. /etc/os-release
case " ${ID:-} ${ID_LIKE:-} " in
  *" debian "*|*" ubuntu "*) family=debian ;;
  *" rhel "*|*" centos "*|*" fedora "*) family=rhel ;;
  *) die "unsupported distribution: ${PRETTY_NAME:-$ID} (Debian, Ubuntu, CentOS/RHEL/Fedora)" ;;
esac

case $(uname -m) in
  x86_64|amd64) arch=x86_64 ;;
  aarch64|arm64) arch=aarch64 ;;
  *) die "unsupported architecture: $(uname -m) (x86_64 or aarch64)" ;;
esac

pkg_install() {
  if [ $family = debian ]; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$@" >/dev/null
  elif command -v dnf >/dev/null; then
    dnf install -y -q "$@" >/dev/null
  else
    yum install -y -q "$@" >/dev/null
  fi
}

apt_updated=0
pkg_ensure() { # install the packages whose command is missing: cmd:pkg ...
  local missing=() item
  for item in "$@"; do
    command -v "${item%%:*}" >/dev/null || missing+=("${item#*:}")
  done
  [ ${#missing[@]} = 0 ] && return
  say "Installing ${missing[*]}"
  if [ $family = debian ] && [ $apt_updated = 0 ]; then
    apt-get update -q >/dev/null
    apt_updated=1
  fi
  pkg_install "${missing[@]}"
}

pkg_ensure curl:curl tar:tar sha256sum:coreutils

# --- download -----------------------------------------------------------------

if [ -z "$version" ]; then
  # The /releases/latest page redirects to /releases/tag/vX.Y.Z; unlike the
  # API it has no rate limit for anonymous clients.
  latest=$(curl -fsSLI -o /dev/null -w '%{url_effective}' \
    "https://github.com/$REPO/releases/latest") || die "cannot reach github.com"
  version=${latest##*/tag/v}
  [ "$version" != "$latest" ] || die "no published release found at github.com/$REPO"
fi
version=${version#v}

name=vykey-server-$version-linux-$arch
base=https://github.com/$REPO/releases/download/v$version

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

say "Downloading vykey-server $version ($arch)"
curl -fsSL -o "$tmp/$name.tar.gz" "$base/$name.tar.gz" \
  || die "download failed: $base/$name.tar.gz"
curl -fsSL -o "$tmp/SHA256SUMS" "$base/SHA256SUMS" \
  || die "download failed: $base/SHA256SUMS"
(cd "$tmp" && grep " $name.tar.gz\$" SHA256SUMS | sha256sum -c --quiet -) \
  || die "checksum mismatch for $name.tar.gz"
tar -C "$tmp" -xzf "$tmp/$name.tar.gz"

# --- install ------------------------------------------------------------------

upgrade=0
[ -x "$BIN" ] && upgrade=1

say "Installing $BIN"
install -m 755 "$tmp/$name/vykey-server" "$BIN.new"
mv -f "$BIN.new" "$BIN"
# Binaries outside the package manager get the wrong SELinux label.
command -v restorecon >/dev/null && restorecon "$BIN" 2>/dev/null || true

if [ ! -e "$UNIT" ]; then
  say "Installing $UNIT"
  install -m 644 "$tmp/$name/vykey-server.service" "$UNIT"
elif ! cmp -s "$tmp/$name/vykey-server.service" "$UNIT"; then
  warn "$UNIT differs from the one in the release; keeping yours"
  warn "(the release version: $base/$name.tar.gz → vykey-server.service)"
fi

systemctl daemon-reload
systemctl enable --quiet vykey-server
if [ $upgrade = 1 ]; then
  say "Restarting vykey-server"
  systemctl restart vykey-server
else
  say "Starting vykey-server"
  systemctl start vykey-server
fi

# Wait until it answers HTTP at all (any status, even 404, means it is up).
for _ in $(seq 10); do
  [ "$(curl -s -o /dev/null -w '%{http_code}' "http://$LISTEN/" || true)" != 000 ] && break
  sleep 1
done
systemctl is-active --quiet vykey-server \
  || die "vykey-server did not start; see: journalctl -u vykey-server"

# --- nginx ---------------------------------------------------------------------

setup_nginx() {
  while [ -z "$domain" ]; do
    ask domain "Domain for the sync server (e.g. sync.example.com)"
    [ -n "$domain" ] || [ -r /dev/tty ] || die "no terminal to ask: pass --domain"
  done
  [[ $domain =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] \
    || die "not a domain name: $domain"

  pkg_ensure nginx:nginx

  local conf
  if [ -d /etc/nginx/sites-available ]; then
    conf=/etc/nginx/sites-available/vykey-server.conf
  else
    conf=/etc/nginx/conf.d/vykey-server.conf
  fi

  if [ -e "$conf" ]; then
    warn "$conf exists; keeping it"
  else
    say "Writing $conf"
    cat >"$conf" <<EOF
# vykey sync server, written by vykey-server's install.sh.
server {
    listen 80;
    listen [::]:80;
    server_name $domain;

    # The server accepts request bodies up to 8 MiB.
    client_max_body_size 9m;

    location / {
        proxy_pass http://$LISTEN;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        # vykey-server runs with --trust-proxy and takes the client address
        # (for rate limits) from the last X-Forwarded-For entry.
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 60s;
    }
}
EOF
    if [ -d /etc/nginx/sites-enabled ]; then
      ln -sf "$conf" /etc/nginx/sites-enabled/vykey-server.conf
    fi
  fi

  # SELinux (CentOS/RHEL) forbids nginx to connect to a local port by default.
  if command -v getenforce >/dev/null && [ "$(getenforce)" != Disabled ]; then
    say "Allowing nginx to connect to the server (SELinux)"
    setsebool -P httpd_can_network_connect 1
  fi

  # Open HTTP/HTTPS if a firewall is running.
  if systemctl is-active --quiet firewalld 2>/dev/null; then
    say "Opening ports 80 and 443 (firewalld)"
    firewall-cmd --quiet --permanent --add-service=http --add-service=https
    firewall-cmd --quiet --reload
  elif command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'; then
    say "Opening ports 80 and 443 (ufw)"
    ufw allow 'Nginx Full' >/dev/null 2>&1 || { ufw allow 80/tcp >/dev/null; ufw allow 443/tcp >/dev/null; }
  fi

  nginx -t -q || die "nginx configuration test failed (nginx -t)"
  systemctl enable --quiet nginx
  systemctl reload-or-restart nginx

  # TLS: the account token travels in every request, so plain HTTP is only
  # fine for testing.
  local tls
  ask tls "Get a Let's Encrypt certificate for $domain? (the domain must already point to this server) [Y/n]" Y
  case $tls in
    [Nn]*)
      warn "no TLS: clients should use https; run certbot --nginx -d $domain later"
      scheme=http
      return ;;
  esac

  if ! command -v certbot >/dev/null; then
    say "Installing certbot"
    if [ $family = rhel ] && [ "${ID:-}" != fedora ]; then
      pkg_install epel-release 2>/dev/null \
        || warn "could not install epel-release; certbot may be unavailable"
    fi
    [ $family = debian ] && [ $apt_updated = 0 ] && { apt-get update -q >/dev/null; apt_updated=1; }
    pkg_install certbot python3-certbot-nginx || die "could not install certbot"
  fi

  [ -n "$email" ] || ask email "Email for Let's Encrypt notices (empty: none)"
  local contact=(--register-unsafely-without-email)
  [ -n "$email" ] && contact=(--email "$email")

  say "Requesting a certificate for $domain"
  if certbot --nginx --non-interactive --agree-tos --redirect "${contact[@]}" -d "$domain"; then
    scheme=https
  else
    warn "certbot failed; nginx keeps serving plain HTTP. Retry: certbot --nginx -d $domain"
    scheme=http
  fi
}

scheme=
[ $with_nginx = 1 ] && setup_nginx

# --- done ---------------------------------------------------------------------

echo
say "vykey-server $version is running ($( [ $upgrade = 1 ] && echo upgraded || echo installed ))"
echo "    status:  systemctl status vykey-server"
echo "    logs:    journalctl -u vykey-server -f"
echo "    data:    /var/lib/vykey-server"
if [ -n "$scheme" ]; then
  echo "    url:     $scheme://$domain"
else
  echo "    listens: http://$LISTEN (local only: put a TLS reverse proxy in front,"
  echo "             or run this script again with --nginx)"
fi
if [ $upgrade = 0 ]; then
  cat <<EOF

Registration is closed by default. To create an account:
    systemctl stop vykey-server
    VYKEY_SERVER_DB=/var/lib/vykey-server/sync.redb $BIN account new
    systemctl start vykey-server
To let invited clients or anyone register, see the comments in $UNIT.
EOF
fi
