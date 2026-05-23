FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/whcp ./cmd/whcp

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/whcp /usr/local/bin/whcp
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/whcp"]
CMD ["api"]
