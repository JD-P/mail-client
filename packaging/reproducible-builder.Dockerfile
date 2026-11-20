# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
FROM rust:1.100.0-trixie@sha256:223cc32ddca8f3ee90c436dbc94b6b5f052ea7f9653c5201e9612f08ad7d21b8

# The base image and every packaging tool are immutable inputs. A disappeared
# package version fails the build instead of silently changing release bytes.
RUN --mount=type=secret,id=proxy_ca,required=false,mode=0444 \
    if [ -s /run/secrets/proxy_ca ]; then \
        export SSL_CERT_FILE=/run/secrets/proxy_ca; \
        export CARGO_HTTP_CAINFO=/run/secrets/proxy_ca; \
    fi \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        binutils=2.44-3 \
        debugedit=1:5.1-2 \
        dpkg-dev=1.22.22 \
        file=1:5.46-5 \
        libarchive13t64=3.7.4-4+deb13u1 \
        libdbus-1-3=1.16.2-2 \
        libdw1t64=0.192-4 \
        libfsverity0=1.6-1.2 \
        liblua5.3-0=5.3.6-2+b4 \
        libpopt0=1.19+dfsg-2 \
        librpm-sequoia-1=1.8.0-2 \
        librpm10=4.20.1+dfsg-3 \
        librpmbuild10=4.20.1+dfsg-3 \
        librpmio10=4.20.1+dfsg-3 \
        librpmsign10=4.20.1+dfsg-3 \
        musl=1.2.5-3.1~deb13u1 \
        musl-dev=1.2.5-3.1~deb13u1 \
        musl-tools=1.2.5-3.1~deb13u1 \
        python3=3.13.5-1 \
        rpm=4.20.1+dfsg-3 \
        rpm-common=4.20.1+dfsg-3 \
        rpm2cpio=4.20.1+dfsg-3 \
    && rm -rf /var/lib/apt/lists/* \
    && rustup target add x86_64-unknown-linux-musl

# Cache Cargo.lock-verified inputs needed by the CLI release. The disposable
# workspace excludes the graphical renderer and its globally patched sources.
# The release invocation itself uses this cache with both the container and
# Cargo in offline mode, and recompiles from the bind-mounted source.
WORKDIR /opt/lizard-mail-source
COPY . .
RUN --mount=type=secret,id=proxy_ca,required=false,mode=0444 \
    --mount=type=cache,id=lizard-mail-cargo-registry,target=/var/cache/lizard-cargo/registry,sharing=locked \
    --mount=type=cache,id=lizard-mail-musl-target,target=/opt/lizard-mail-source/target,sharing=locked \
    if [ -s /run/secrets/proxy_ca ]; then \
        export SSL_CERT_FILE=/run/secrets/proxy_ca; \
        export CARGO_HTTP_CAINFO=/run/secrets/proxy_ca; \
    fi \
    && python3 packaging/prepare-cli-workspace.py . \
    && install -m 0644 packaging/Cargo.cli.lock Cargo.lock \
    && CARGO_HOME=/var/cache/lizard-cargo cargo build --locked --release \
        --target x86_64-unknown-linux-musl \
        -p lizard-mail-tui \
        -p lizard-mail-backend \
        --bins \
    && rm -rf /usr/local/cargo/registry /usr/local/cargo/git \
    && cp -a /var/cache/lizard-cargo/registry /usr/local/cargo/

WORKDIR /src
