# syntax=docker/dockerfile:1
FROM golang:1.26-bookworm AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/bridge-monitor .

FROM debian:bookworm-slim AS prod
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/bridge-monitor /usr/local/bin/bridge-monitor

EXPOSE 9100 8080
ENTRYPOINT ["bridge-monitor"]
