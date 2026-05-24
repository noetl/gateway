FROM alpine:3.23 AS base

ENV TERM=xterm-256color
RUN apk add --no-cache rust cargo pkgconfig openssl-dev curl

FROM base AS build

WORKDIR /app
COPY . .
RUN cargo build --release


FROM alpine:3.23 AS runtime

WORKDIR /app
RUN apk add --no-cache libgcc libxslt ca-certificates openssl python3 py3-pip \
    && python3 -m venv /opt/firestore-sidecar
COPY requirements-firestore.txt ./requirements-firestore.txt
RUN /opt/firestore-sidecar/bin/pip install --no-cache-dir -r requirements-firestore.txt
COPY --from=build /app/target/release/noetl-gateway ./noetl-gateway
COPY scripts ./scripts
ENV GATEWAY_FIRESTORE_LISTENER_CMD="/opt/firestore-sidecar/bin/python scripts/firestore_listener.py"

EXPOSE 8090

ENTRYPOINT ["./noetl-gateway"]
