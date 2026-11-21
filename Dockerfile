FROM rust:1.100-trixie AS chef

COPY --from=node:22-trixie-slim /usr/local/bin/node /usr/local/bin/
COPY --from=node:22-trixie-slim /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
    && npm install -g pnpm@10

RUN cargo install cargo-chef

FROM chef AS planner

WORKDIR /app
COPY . .
# Create a Recipe based on the crate
RUN cargo chef prepare  --recipe-path recipe.json

FROM planner AS builder

# Copy the recipe to next stage
COPY --from=planner /app/recipe.json recipe.json

# Build the dependencies
RUN cargo chef cook --release --recipe-path recipe.json
# Copy the code to build layer
COPY . .

RUN curl -LO https://rolesanywhere.amazonaws.com/releases/1.8.6/X86_64/Linux/Amzn2023/aws_signing_helper

# Build the binary
RUN cargo build --release

FROM debian:trixie-slim

WORKDIR /app

COPY --from=builder /app/aws_signing_helper /usr/bin
COPY --from=builder /app/target/release/griffin-mail /usr/local/bin/app
COPY --from=builder /app/config.toml /app/config.toml

RUN apt update
RUN apt install openssl ca-certificates -y

EXPOSE 8080

CMD ["/usr/local/bin/app"]
