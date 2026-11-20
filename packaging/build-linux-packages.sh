#!/bin/bash -p
set -euo pipefail

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
LC_ALL=C
TZ=UTC
export LC_ALL TZ
unset CDPATH ENV BASH_ENV
umask 022

usage() {
    echo "Usage: $0 --bin-dir DIR --version VERSION --output DIR" >&2
    exit 2
}

bin_dir=
version=
output=
while (($#)); do
    case "$1" in
        --bin-dir)
            (($# >= 2)) || usage
            bin_dir=$2
            shift 2
            ;;
        --version)
            (($# >= 2)) || usage
            version=$2
            shift 2
            ;;
        --output)
            (($# >= 2)) || usage
            output=$2
            shift 2
            ;;
        *) usage ;;
    esac
done

[[ -n "$bin_dir" && -n "$version" && -n "$output" ]] || usage
[[ "$version" =~ ^[0-9][0-9A-Za-z.+~-]*$ ]] || {
    echo "packaging: unsupported version: $version" >&2
    exit 1
}
source_date_epoch=${SOURCE_DATE_EPOCH:-0}
[[ "$source_date_epoch" =~ ^[0-9]+$ ]] || {
    echo "packaging: SOURCE_DATE_EPOCH must be a non-negative integer" >&2
    exit 1
}
export SOURCE_DATE_EPOCH=$source_date_epoch

for command in dpkg-deb file gzip readelf rpmbuild sha256sum tar; do
    command -v "$command" >/dev/null || {
        echo "packaging: missing required command: $command" >&2
        exit 1
    }
done

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo_root=$(cd -- "$script_dir/.." && pwd -P)
bin_dir=$(cd -- "$bin_dir" && pwd -P)
output=$(mkdir -p -- "$output" && cd -- "$output" && pwd -P)
work_dir=$(mktemp -d)
trap 'rm -rf -- "$work_dir"' EXIT INT TERM

binaries=(
    lizard-mail-tui
    lizard-mail-tui-render-worker
    lizard-mail-sync-worker
    lizard-mail-archive-worker
)
for binary in "${binaries[@]}"; do
    path="$bin_dir/$binary"
    [[ -f "$path" && -x "$path" ]] || {
        echo "packaging: missing executable: $path" >&2
        exit 1
    }
    if readelf -d "$path" 2>/dev/null | grep -q '(NEEDED)'; then
        echo "packaging: $binary unexpectedly has dynamic dependencies" >&2
        exit 1
    fi
    readelf -h "$path" | grep -q 'Machine:.*Advanced Micro Devices X86-64' || {
        echo "packaging: $binary is not x86-64" >&2
        exit 1
    }
    [[ "$("$path" --version)" == "$binary $version" ]] || {
        echo "packaging: $binary does not report release version $version" >&2
        exit 1
    }
done

release=1
deb_name="lizard-mail_${version}-${release}_amd64.deb"
rpm_version=${version//-/~}
rpm_name="lizard-mail-${rpm_version}-${release}.x86_64.rpm"
archive_root_name="lizard-mail-${version}-linux-x86_64-musl"
archive_name="$archive_root_name.tar.gz"

archive_root="$work_dir/$archive_root_name"
for binary in "${binaries[@]}"; do
    install -Dm 0755 "$bin_dir/$binary" "$archive_root/$binary"
done
install -Dm 0644 "$script_dir/README.md" "$archive_root/PACKAGING.md"
install -Dm 0644 "$repo_root/LICENSE" "$archive_root/LICENSE"
find "$archive_root" -depth -exec touch -h -d "@$source_date_epoch" -- {} +
tar --sort=name --mtime="@$source_date_epoch" --owner=0 --group=0 --numeric-owner \
    -C "$work_dir" -cf - "$archive_root_name" \
    | gzip -n >"$output/$archive_name"

deb_root="$work_dir/deb"
install -Dm 0755 "$bin_dir/lizard-mail-tui" "$deb_root/usr/bin/lizard-mail-tui"
for worker in "${binaries[@]:1}"; do
    install -Dm 0755 "$bin_dir/$worker" "$deb_root/usr/libexec/lizard-mail/$worker"
done
install -Dm 0644 "$script_dir/README.md" "$deb_root/usr/share/doc/lizard-mail/PACKAGING.md"
install -Dm 0644 "$repo_root/LICENSE" "$deb_root/usr/share/doc/lizard-mail/copyright"
install -d -m 0755 "$deb_root/DEBIAN"
cat >"$deb_root/DEBIAN/control" <<EOF
Package: lizard-mail
Version: ${version}-${release}
Section: mail
Priority: optional
Architecture: amd64
Maintainer: Lizard contributors <noreply@github.com>
Homepage: https://github.com/JD-P/mail-client
Description: local-first terminal mail client with isolated content workers
 Lizard Mail is an opinionated terminal mail client with warm, cold and spam
 workflows. Hostile IMAP, ZIP and HTML inputs are handled by disposable,
 capability-restricted worker processes.
EOF
find "$deb_root" -depth -exec touch -h -d "@$source_date_epoch" -- {} +
dpkg-deb --root-owner-group -Zxz -z6 --build "$deb_root" "$output/$deb_name"

rpm_top="$work_dir/rpm"
mkdir -p "$rpm_top"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS,rpmdb}
for binary in "${binaries[@]}"; do
    install -m 0755 "$bin_dir/$binary" "$rpm_top/SOURCES/$binary"
done
install -m 0644 "$script_dir/README.md" "$rpm_top/SOURCES/PACKAGING.md"
install -m 0644 "$repo_root/LICENSE" "$rpm_top/SOURCES/LICENSE"
cat >"$rpm_top/SPECS/lizard-mail.spec" <<EOF
Name:           lizard-mail
Version:        ${rpm_version}
Release:        ${release}
Summary:        Local-first terminal mail client with isolated content workers
License:        MIT
URL:            https://github.com/JD-P/mail-client
Source0:        lizard-mail-tui
Source1:        lizard-mail-tui-render-worker
Source2:        lizard-mail-sync-worker
Source3:        lizard-mail-archive-worker
Source4:        PACKAGING.md
Source5:        LICENSE
BuildArch:      x86_64
AutoReqProv:    no
%global __os_install_post %{nil}

%description
Lizard Mail is an opinionated terminal mail client. Hostile IMAP, ZIP and HTML
inputs are handled by disposable, capability-restricted worker processes.

%prep

%build

%install
install -Dm 0755 %{SOURCE0} %{buildroot}/usr/bin/lizard-mail-tui
install -Dm 0755 %{SOURCE1} %{buildroot}/usr/libexec/lizard-mail/lizard-mail-tui-render-worker
install -Dm 0755 %{SOURCE2} %{buildroot}/usr/libexec/lizard-mail/lizard-mail-sync-worker
install -Dm 0755 %{SOURCE3} %{buildroot}/usr/libexec/lizard-mail/lizard-mail-archive-worker
install -Dm 0644 %{SOURCE4} %{buildroot}/usr/share/doc/lizard-mail/PACKAGING.md
install -Dm 0644 %{SOURCE5} %{buildroot}/usr/share/licenses/lizard-mail/LICENSE
find %{buildroot} -depth -exec touch -h -d '@${source_date_epoch}' -- {} +

%files
%attr(0755,root,root) /usr/bin/lizard-mail-tui
%attr(0755,root,root) /usr/libexec/lizard-mail/lizard-mail-tui-render-worker
%attr(0755,root,root) /usr/libexec/lizard-mail/lizard-mail-sync-worker
%attr(0755,root,root) /usr/libexec/lizard-mail/lizard-mail-archive-worker
%doc /usr/share/doc/lizard-mail/PACKAGING.md
%license /usr/share/licenses/lizard-mail/LICENSE
EOF
find "$rpm_top/SOURCES" "$rpm_top/SPECS" -depth \
    -exec touch -h -d "@$source_date_epoch" -- {} +
rpmbuild --define "_topdir $rpm_top" \
    --define "_dbpath $rpm_top/rpmdb" \
    --define "_build_id_links none" \
    --define "_buildhost reproducible.invalid" \
    --define "use_source_date_epoch_as_buildtime 1" \
    --define "clamp_mtime_to_source_date_epoch 1" \
    -bb "$rpm_top/SPECS/lizard-mail.spec"
rpm_path=$(find "$rpm_top/RPMS" -type f -name '*.rpm' -print -quit)
[[ -n "$rpm_path" ]] || {
    echo "packaging: rpmbuild did not produce an RPM" >&2
    exit 1
}
install -m 0644 "$rpm_path" "$output/$rpm_name"

(
    cd -- "$output"
    sha256sum "$archive_name" "$deb_name" "$rpm_name" >SHA256SUMS
)

printf 'packaging: wrote artifacts to %s\n' "$output"
