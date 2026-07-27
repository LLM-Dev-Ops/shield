# syntax=docker/dockerfile:1.7
# Multi-stage Dockerfile for LLM Shield API
# Optimizes for size (<50MB), security (distroless), and build speed (layer caching)
#
# The workspace pulls 16 crates from the private repo LLM-Dev-Ops/infra, so the
# build requires a GitHub token with Contents:read supplied as a BuildKit secret.
#
# Build: DOCKER_BUILDKIT=1 docker build --secret id=gh_token,src=<token-file> \
#          -t llm-shield-api:latest .
# Run:   docker run -p 8080:8080 llm-shield-api:latest

# ==============================================================================
# Stage 1: Build Environment
# ==============================================================================
# Debian 13 (glibc 2.41), NOT bookworm (2.36): the `ort` crate links a prebuilt
# ONNX Runtime that references __isoc23_strtol/strtoll/strtoull, added in glibc
# 2.38. On bookworm the final link fails with undefined symbols. The runtime
# stage below must stay on the matching debian13 distroless. See ADR-0002.
FROM rust:1.93-slim-trixie AS builder

WORKDIR /build

# Install build dependencies.
# git: rust:slim does not ship it, and the url.insteadOf rewrite below needs it.
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    curl \
    g++ \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace configuration and lockfile
COPY Cargo.toml Cargo.lock ./

# Copy all crate manifests for dependency caching (must match workspace members)
COPY crates/llm-shield-core/Cargo.toml crates/llm-shield-core/
COPY crates/llm-shield-models/Cargo.toml crates/llm-shield-models/
COPY crates/llm-shield-nlp/Cargo.toml crates/llm-shield-nlp/
COPY crates/llm-shield-scanners/Cargo.toml crates/llm-shield-scanners/
COPY crates/llm-shield-secrets/Cargo.toml crates/llm-shield-secrets/
COPY crates/llm-shield-anonymize/Cargo.toml crates/llm-shield-anonymize/
COPY crates/llm-shield-api/Cargo.toml crates/llm-shield-api/
COPY crates/llm-shield-wasm/Cargo.toml crates/llm-shield-wasm/
COPY crates/llm-shield-py/Cargo.toml crates/llm-shield-py/
COPY crates/llm-shield-cloud/Cargo.toml crates/llm-shield-cloud/
COPY crates/llm-shield-cloud-aws/Cargo.toml crates/llm-shield-cloud-aws/
COPY crates/llm-shield-cloud-gcp/Cargo.toml crates/llm-shield-cloud-gcp/
COPY crates/llm-shield-cloud-azure/Cargo.toml crates/llm-shield-cloud-azure/
COPY crates/llm-shield-sdk/Cargo.toml crates/llm-shield-sdk/
COPY crates/llm-shield-benchmarks/Cargo.toml crates/llm-shield-benchmarks/
COPY crates/llm-security-core/Cargo.toml crates/llm-security-core/

# Create dummy source files to build dependencies (cached layer)
RUN for crate in llm-shield-core llm-shield-models llm-shield-nlp llm-shield-scanners \
    llm-shield-secrets llm-shield-anonymize llm-shield-wasm llm-shield-py \
    llm-shield-cloud llm-shield-cloud-aws llm-shield-cloud-gcp llm-shield-cloud-azure \
    llm-shield-sdk llm-shield-benchmarks llm-security-core; do \
      mkdir -p crates/$crate/src && echo "pub fn placeholder() {}" > crates/$crate/src/lib.rs; \
    done && \
    mkdir -p crates/llm-shield-api/src && \
    echo "fn main() {}" > crates/llm-shield-api/src/main.rs && \
    echo "pub fn placeholder() {}" > crates/llm-shield-api/src/lib.rs && \
    mkdir -p crates/llm-shield-models/benches && \
    echo "fn main() {}" > crates/llm-shield-models/benches/cache_bench.rs && \
    echo "fn main() {}" > crates/llm-shield-models/benches/registry_bench.rs && \
    mkdir -p crates/llm-shield-api/benches && \
    echo "fn main() {}" > crates/llm-shield-api/benches/api_bench.rs && \
    mkdir -p crates/llm-shield-cloud/benches && \
    echo "fn main() {}" > crates/llm-shield-cloud/benches/cloud_bench.rs

# Build dependencies only (this layer will be cached).
# The workspace depends on the private repo github.com/LLM-Dev-Ops/infra. The
# token arrives as a BuildKit secret mounted only for the duration of this RUN
# (tmpfs, never a layer) and the url.insteadOf rewrite is unset before the
# layer commits, so the credential never reaches the image. See ADR-0002.
RUN --mount=type=secret,id=gh_token \
    git config --global \
      url."https://x-access-token:$(cat /run/secrets/gh_token)@github.com/".insteadOf \
      "https://github.com/" && \
    cargo build --release --bin llm-shield-api && \
    rm -rf target/release/deps/llm_shield* target/release/deps/llm_security* \
           target/release/deps/libllm_shield* target/release/deps/libllm_security* && \
    git config --global --unset-all \
      url."https://x-access-token:$(cat /run/secrets/gh_token)@github.com/".insteadOf

# Copy actual source code
COPY crates ./crates

# Build the application
RUN --mount=type=secret,id=gh_token \
    git config --global \
      url."https://x-access-token:$(cat /run/secrets/gh_token)@github.com/".insteadOf \
      "https://github.com/" && \
    cargo build --release --bin llm-shield-api && \
    git config --global --unset-all \
      url."https://x-access-token:$(cat /run/secrets/gh_token)@github.com/".insteadOf

# Strip debug symbols to reduce binary size
RUN strip target/release/llm-shield-api

# ==============================================================================
# Stage 2: Runtime Environment (Distroless for Security)
# ==============================================================================
# Must match the builder's Debian release (glibc 2.41) — see the builder note.
FROM gcr.io/distroless/cc-debian13

# Metadata
LABEL maintainer="LLM Shield Team"
LABEL description="LLM Shield API - Production-ready LLM security scanning"
LABEL version="1.0"

# Copy binary from builder
COPY --from=builder /build/target/release/llm-shield-api /usr/local/bin/llm-shield-api

# Copy ML models if they exist (optional)
# COPY --from=builder /build/models /opt/llm-shield/models

# Non-root user (distroless default: nonroot:nonroot UID/GID 65532)
USER nonroot:nonroot

# Expose API port (8080) and metrics port (9090)
EXPOSE 8080 9090

# Health check (requires curl in distroless - use custom health check externally)
# HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
#     CMD ["/usr/local/bin/llm-shield-api", "health"]

# Run the application
ENTRYPOINT ["/usr/local/bin/llm-shield-api"]
CMD []

# ==============================================================================
# Build Information
# ==============================================================================
# Expected image size: ~50MB (vs ~500MB with full Rust image)
# Security features:
#   - Distroless base (minimal attack surface, no shell)
#   - Non-root user
#   - Read-only root filesystem (set via K8s securityContext)
#   - Dropped capabilities (set via K8s securityContext)
#
# Build time optimization:
#   - Dependency caching: Only rebuilds when Cargo.toml changes
#   - Multi-stage: Discards build dependencies (~450MB savings)
#   - Binary stripping: Removes debug symbols (~20% size reduction)
