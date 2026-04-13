# deploy/Dockerfile.builder — Cross-platform build container for PKI releases
#
# Produces linux/amd64 BEAM releases from macOS Apple Silicon.
#
# Usage:
#   # One-time: build the builder image
#   podman build --platform linux/amd64 -t pki-builder -f deploy/Dockerfile.builder .
#
#   # Build releases (run from repo root)
#   bash deploy/build-container.sh
#
# What this does:
#   1. Installs Erlang/OTP 27 + Elixir 1.18 (matching production)
#   2. Installs liboqs (for pki_oqs_nif NIF compilation)
#   3. Installs Node.js (for Phoenix asset pipeline)
#   4. Mounts your source code and runs build.sh inside the container
#   5. Outputs tarballs to deploy/releases/

FROM --platform=linux/amd64 hexpm/elixir:1.18.4-erlang-27.3.4-ubuntu-jammy-20250404

ARG DEBIAN_FRONTEND=noninteractive

# ── System dependencies ──────────────────────────────────────────────────────
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    ninja-build \
    git \
    ca-certificates \
    curl \
    libssl-dev \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

# ── liboqs (post-quantum crypto library) ─────────────────────────────────────
# Build from source — Ubuntu 22.04 doesn't have liboqs-dev in apt
ARG LIBOQS_VERSION=0.12.0
RUN cd /tmp \
    && curl -fsSL "https://github.com/open-quantum-safe/liboqs/archive/refs/tags/${LIBOQS_VERSION}.tar.gz" \
       | tar xz \
    && cd "liboqs-${LIBOQS_VERSION}" \
    && mkdir build && cd build \
    && cmake -GNinja .. \
       -DCMAKE_INSTALL_PREFIX=/usr/local \
       -DBUILD_SHARED_LIBS=OFF \
       -DOQS_BUILD_ONLY_LIB=ON \
       -DOQS_USE_OPENSSL=ON \
    && ninja && ninja install \
    && rm -rf /tmp/liboqs-*

# ── Hex + Rebar ──────────────────────────────────────────────────────────────
RUN mix local.hex --force && mix local.rebar --force

# ── Working directory ────────────────────────────────────────────────────────
# Set to /workspace — the build script overrides to /workspace/pki via -w flag.
# This allows sibling repos (PQC-KAZ) to be accessible via relative paths.
WORKDIR /workspace

# Default: run the build script
CMD ["bash", "deploy/build.sh"]
