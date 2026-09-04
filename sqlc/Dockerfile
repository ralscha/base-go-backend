FROM golang:1.27.1

RUN go install github.com/sqlc-dev/sqlc/cmd/sqlc@v1.31.1

WORKDIR /src/

CMD ["sh", "-lc", "/go/bin/sqlc generate -f /src/sqlc/sqlc.yaml"]
