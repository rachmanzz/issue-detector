# Multi-stage build: static binary on a minimal, non-root base.
FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# modernc.org/sqlite is pure Go, so CGO can stay off for a static binary.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/issue-detector ./cmd/issue-detector

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/issue-detector /usr/local/bin/issue-detector
ENTRYPOINT ["/usr/local/bin/issue-detector"]
