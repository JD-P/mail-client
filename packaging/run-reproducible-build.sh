#!/bin/bash -p
set -euo pipefail

LC_ALL=C
export LC_ALL
unset CDPATH ENV BASH_ENV
umask 022

for command in docker git; do
    command -v "$command" >/dev/null || {
        echo "reproducible-builder: missing required command: $command" >&2
        exit 1
    }
done

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo_root=$(cd -- "$script_dir/.." && pwd -P)
source_date_epoch=${SOURCE_DATE_EPOCH:-$(git -C "$repo_root" log -1 --format=%ct)}
[[ "$source_date_epoch" =~ ^[0-9]+$ ]] || {
    echo "reproducible-builder: SOURCE_DATE_EPOCH must be a non-negative integer" >&2
    exit 1
}

image=lizard-mail-reproducible-builder:rust-1.100.0-debian-20261120
build_secrets=()
if [[ -n "${CODEX_PROXY_CERT:-}" && -r "$CODEX_PROXY_CERT" ]]; then
    build_secrets+=(--secret "id=proxy_ca,src=$CODEX_PROXY_CERT")
fi
docker build \
    "${build_secrets[@]}" \
    --file "$script_dir/reproducible-builder.Dockerfile" \
    --tag "$image" \
    "$repo_root"

docker run --rm --network none \
    --env CARGO_NET_OFFLINE=true \
    --env SOURCE_DATE_EPOCH="$source_date_epoch" \
    --env LIZARD_BUILD_UID="$(id -u)" \
    --env LIZARD_BUILD_GID="$(id -g)" \
    --mount "type=bind,src=$repo_root,dst=/src" \
    --workdir /src \
    "$image" \
    bash -c '
        set -euo pipefail
        cp -a /usr/local/cargo /tmp/cargo-home
        chown -R "$LIZARD_BUILD_UID:$LIZARD_BUILD_GID" /tmp/cargo-home
        exec setpriv \
            --reuid="$LIZARD_BUILD_UID" \
            --regid="$LIZARD_BUILD_GID" \
            --clear-groups \
            env CARGO_HOME=/tmp/cargo-home \
            /src/packaging/reproducible-build.sh "$@"
    ' bash "$@"
