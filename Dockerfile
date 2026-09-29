# syntax=docker/dockerfile:1
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/hive-agent ./cmd/hive-agent \
 && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/hive-gateway ./cmd/hive-gateway \
 && mkdir -p /out/cluster

# scratch: nothing but the static binaries and CA roots (for https webhooks
# and capability key exchange). Avoids a second registry (gcr.io) that is
# unreachable from some networks.
FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/hive-agent /usr/local/bin/hive-agent
COPY --from=build /out/hive-gateway /usr/local/bin/hive-gateway
# Named volumes mounted here inherit this ownership, so the non-root user
# can write generated keys.
COPY --from=build --chown=65532:65532 /out/cluster /cluster
USER 65532:65532
# 7946 gossip; 8787 gateway admin plane (bind it to localhost).
EXPOSE 7946 8787
ENTRYPOINT ["/usr/local/bin/hive-agent"]
CMD ["version"]
