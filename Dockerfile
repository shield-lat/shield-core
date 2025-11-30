# Build stage
# Using rust:latest to get edition 2024 support (requires Rust 1.85+)
FROM rust:latest AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy manifests first for better caching
COPY Cargo.toml Cargo.lock ./

# Create dummy src to build dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Build dependencies only
RUN cargo build --release && rm -rf src

# Copy actual source code
COPY src ./src
COPY config ./config

# Build the application
RUN touch src/main.rs && cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libsqlite3-0 \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/shield-core /app/shield-core

# Copy config
COPY config ./config

# Create data directory for SQLite
RUN mkdir -p /app/data

# Set environment variables
ENV SHIELD_SERVER__HOST=0.0.0.0
ENV SHIELD_DATABASE__URL=sqlite:/app/data/shield.db?mode=rwc
ENV RUST_LOG=shield_core=info,tower_http=info

# Railway provides PORT env var - we'll read it in the app
# Default to 8080 if not set
ENV PORT=8080

# Run the application with shell to expand $PORT
CMD ["sh", "-c", "SHIELD_SERVER__PORT=$PORT ./shield-core"]

