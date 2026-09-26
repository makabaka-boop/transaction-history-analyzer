FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY audit/ audit/
COPY cmd/ cmd/
RUN CGO_ENABLED=0 go build -o /out/txcheck ./cmd/txcheck

FROM alpine:3.20
RUN adduser -D -u 10001 auditor
COPY --from=build /out/txcheck /usr/local/bin/txcheck
USER auditor
ENTRYPOINT ["txcheck"]
