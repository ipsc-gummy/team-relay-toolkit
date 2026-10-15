#!/usr/bin/env bash
# 仅对显式确认的 Linux 主机进行全新安装，不覆盖既有服务。
set -euo pipefail
umask 077

source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
expected_hostname=${RELAY_EXPECTED_HOSTNAME:?必须显式设置 RELAY_EXPECTED_HOSTNAME 为目标主机 hostname}
release_url=https://github.com/router-for-me/CLIProxyAPI/releases/download/v7.2.155/CLIProxyAPI_7.2.155_linux_amd64.tar.gz
release_sha256=5eb8e1ab3f90aa22e4843d0c881f113d4e359a8cb3d3ec130a53e356060be730

if [[ $(id -u) != 0 || $(hostname) != "$expected_hostname" || $(uname -m) != x86_64 ]]; then
  printf 'STOP: unexpected host, user, or architecture.\n' >&2
  exit 1
fi
for target in /opt/cliproxyapi /etc/cliproxyapi /var/lib/cliproxyapi /etc/systemd/system/cliproxyapi.service; do
  if [[ -e $target || -L $target ]]; then
    printf 'STOP: existing target: %s\n' "$target" >&2
    exit 1
  fi
done
if getent passwd cliproxyapi >/dev/null || getent group cliproxyapi >/dev/null; then
  printf 'STOP: service account or group already exists.\n' >&2
  exit 1
fi
if ss -Hlnt 'sport = :8317' | read -r _; then
  printf 'STOP: port 8317 is in use.\n' >&2
  exit 1
fi

release_dir=$(mktemp -d /tmp/cliproxyapi-release.XXXXXX)
curl --noproxy '*' --fail --location --silent --show-error \
  --connect-timeout 10 --max-time 180 --retry 2 \
  --output "$release_dir/release.tar.gz" "$release_url"
printf '%s  %s\n' "$release_sha256" "$release_dir/release.tar.gz" | sha256sum --check --status
printf 'RELEASE_SHA256=PASS\n'
tar -xzf "$release_dir/release.tar.gz" -C "$release_dir" cli-proxy-api LICENSE
[[ -f $release_dir/cli-proxy-api && ! -L $release_dir/cli-proxy-api ]]

useradd --system --user-group --home-dir /var/lib/cliproxyapi \
  --no-create-home --shell /usr/sbin/nologin cliproxyapi
install -d -m 0755 /opt/cliproxyapi /opt/cliproxyapi/v7.2.155
install -m 0755 "$release_dir/cli-proxy-api" /opt/cliproxyapi/v7.2.155/cli-proxy-api
install -m 0644 "$release_dir/LICENSE" /opt/cliproxyapi/v7.2.155/LICENSE
install -d -m 0750 -o root -g cliproxyapi /etc/cliproxyapi
install -d -m 0700 -o cliproxyapi -g cliproxyapi /var/lib/cliproxyapi /var/lib/cliproxyapi/auth

relay_api_key="cpa-owner-$(openssl rand -hex 32)"
install -m 0640 -o root -g cliproxyapi "$source_dir/config.template.yaml" /etc/cliproxyapi/config.yaml
sed -i "s/__RELAY_API_KEY__/$relay_api_key/" /etc/cliproxyapi/config.yaml
printf 'header = "Authorization: Bearer %s"\n' "$relay_api_key" > /etc/cliproxyapi/owner-client.curl
chmod 0600 /etc/cliproxyapi/owner-client.curl
unset relay_api_key

install -m 0644 "$source_dir/cliproxyapi.service" /etc/systemd/system/cliproxyapi.service
systemd-analyze verify /etc/systemd/system/cliproxyapi.service
systemctl daemon-reload
systemctl enable --now cliproxyapi.service
ready=false
for attempt in {1..20}; do
  if curl --noproxy '*' --fail --silent --max-time 2 http://127.0.0.1:8317/ >/dev/null; then
    ready=true
    break
  fi
  sleep 0.5
done
[[ $ready == true ]]

unauth_status=$(curl --noproxy '*' --silent --output /dev/null --write-out '%{http_code}' http://127.0.0.1:8317/v1/models)
invalid_status=$(curl --noproxy '*' --silent --output /dev/null --write-out '%{http_code}' -H 'Authorization: Bearer invalid-test-key' http://127.0.0.1:8317/v1/models)
auth_status=$(curl --noproxy '*' --silent --output /dev/null --write-out '%{http_code}' --config /etc/cliproxyapi/owner-client.curl http://127.0.0.1:8317/v1/models)
management_status=$(curl --noproxy '*' --silent --output /dev/null --write-out '%{http_code}' http://127.0.0.1:8317/v0/management/config)
printf 'UNAUTH_HTTP=%s INVALID_KEY_HTTP=%s AUTH_HTTP=%s MANAGEMENT_HTTP=%s\n' "$unauth_status" "$invalid_status" "$auth_status" "$management_status"
[[ $unauth_status == 401 && $invalid_status == 401 && $auth_status == 200 && $management_status == 404 ]]
systemctl is-enabled cliproxyapi.service
systemctl is-active cliproxyapi.service
systemctl show cliproxyapi.service -p MainPID -p MemoryCurrent -p TasksCurrent -p NRestarts
ss -Hlntp 'sport = :8317'
printf 'MODELS_BEFORE_OAUTH='
curl --noproxy '*' --fail --silent --show-error --config /etc/cliproxyapi/owner-client.curl http://127.0.0.1:8317/v1/models
printf '\nINSTALL=PASS; INFERENCE=NOT_RUN; OAUTH=AWAITING_USER\n'
printf 'DOWNLOAD_CACHE=%s\n' "$release_dir"
