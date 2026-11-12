# Image dédiée du log store (décision du ticket #1 : pas de 3e binaire dans l'image de l'analyseur).
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X ngxops/logstore/internal/api.Version=${VERSION}" \
    -o /out/logstore ./cmd/logstore

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/logstore /logstore
USER nonroot:nonroot
EXPOSE 8443
# Pas de shell dans l'image : la sonde est un sous-commande du binaire.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD ["/logstore", "healthcheck"]
ENTRYPOINT ["/logstore"]
