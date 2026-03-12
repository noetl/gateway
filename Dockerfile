FROM alpine:3.23 AS base

ENV TERM=xterm-256color
RUN apk add --no-cache rust cargo pkgconfig openssl-dev curl

FROM base AS build

WORKDIR /app
COPY . .
RUN cargo build --release


FROM alpine:3.23 AS runtime

WORKDIR /app
RUN apk add --no-cache libgcc libxslt ca-certificates openssl
COPY --from=build /app/target/release/noetl-gateway ./noetl-gateway

EXPOSE 8090

ENTRYPOINT ["./noetl-gateway"]
