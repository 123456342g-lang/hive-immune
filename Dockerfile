# syntax=docker/dockerfile:1
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/hive-agent ./cmd/hive-agent \
 && mkdir -p /out/cluster

# scratch: nothing but the static binary and CA roots (for https webhooks).
# Avoids a second registry (gcr.io) that is unreachable from some networks.
FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/hive-agent /usr/local/bin/hive-agent
# Named volumes mounted here inherit this ownership, so the non-root user
# can write generated keys.
COPY --from=build --chown=65532:65532 /out/cluster /cluster
USER 65532:65532
EXPOSE 7946
ENTRYPOINT ["/usr/local/bin/hive-agent"]
CMD ["version"]
