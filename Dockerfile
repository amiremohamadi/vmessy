FROM rust:1.76-alpine3.18

COPY src ./src
COPY Cargo.lock Cargo.toml .

RUN apk update && apk add musl-dev
RUN cargo build --release

WORKDIR ./target/release

CMD ["./vmessy", "--config", "/etc/config/config.toml"]
