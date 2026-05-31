# syntax=docker/dockerfile:1

# --- build stage -------------------------------------------------------------
FROM golang:1.26 AS build
WORKDIR /src

# Cache module downloads.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# Static, stripped binaries (CGO off → runnable on distroless/static).
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/api ./cmd/api && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/worker ./cmd/worker

# --- runtime stage -----------------------------------------------------------
# distroless/static:nonroot → no shell, no package manager, runs as UID 65532.
FROM gcr.io/distroless/static:nonroot
WORKDIR /app
COPY --from=build /out/api /app/api
COPY --from=build /out/worker /app/worker

# Drop privileges (distroless nonroot already maps to 65532; make it explicit).
USER 65532:65532
EXPOSE 8080

# Default to the API; override the entrypoint to run the worker:
#   docker run --entrypoint /app/worker <image>
ENTRYPOINT ["/app/api"]
