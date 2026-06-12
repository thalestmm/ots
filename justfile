# OTS task runner — https://github.com/casey/just

default:
    @just --list

# Run the relay API locally (public upstream calendars)
run:
    go run ./cmd/server

# Run relay with custom upstream calendars
run-calendars urls:
    go run ./cmd/server -calendars "{{urls}}"

# Build relay server binary to bin/ots-server
build:
    mkdir -p bin
    go build -o bin/ots-server ./cmd/server

# Build self-hosted calendar server binary
build-calendar:
    mkdir -p bin
    go build -o bin/ots-calendar ./cmd/calendar

# Run all tests
test:
    go test ./...

# Run tests incl. regtest integration (needs `just regtest-up` first)
test-all:
    OTS_REGTEST_RPC_HOST=127.0.0.1:18443 \
    OTS_REGTEST_RPC_USER=ots OTS_REGTEST_RPC_PASS=ots \
    go test ./...

# Start a disposable bitcoind regtest node with a funded wallet (docker)
regtest-up:
    docker rm -f ots-regtest 2>/dev/null || true
    docker run -d --name ots-regtest -p 18443:18443 bitcoin/bitcoin:28 \
        -regtest=1 -rpcallowip=0.0.0.0/0 -rpcbind=0.0.0.0 \
        -rpcuser=ots -rpcpassword=ots -fallbackfee=0.0001
    sleep 3
    docker exec ots-regtest bitcoin-cli -regtest -rpcuser=ots -rpcpassword=ots createwallet stamper
    docker exec ots-regtest bitcoin-cli -regtest -rpcuser=ots -rpcpassword=ots -rpcwallet=stamper -generate 101 > /dev/null
    @echo "regtest node ready on 127.0.0.1:18443 (user/pass: ots/ots)"

# Tear down the regtest node
regtest-down:
    docker rm -f ots-regtest

# Run the calendar server against the regtest node (self-hosted calendar mode)
calendar-run-regtest:
    go run ./cmd/calendar \
        -btc-rpc-host 127.0.0.1:18443 -btc-rpc-user ots -btc-rpc-pass ots \
        -btc-network regtest -btc-min-confirmations 1 -btc-min-tx-interval 5s \
        -data-dir /tmp/ots-regtest-data

# Run calendar server locally (in-memory, no Bitcoin)
calendar-run:
    go run ./cmd/calendar -data-dir memory

# Run calendar server with persistence
calendar-run-persistent:
    go run ./cmd/calendar

# Mine n regtest blocks (confirms pending anchors)
regtest-mine n="1":
    docker exec ots-regtest bitcoin-cli -regtest -rpcuser=ots -rpcpassword=ots -rpcwallet=stamper -generate {{n}}

# Cross-validate wire format against the Python reference client (needs uv + running calendar on :14788)
cross-validate:
    ./scripts/cross-validate.sh

# First-boot calendar setup: create data dir, key, and URI
setup-calendar uri data_dir="~/.otsd/calendar":
    @mkdir -p {{data_dir}}
    @test -f {{data_dir}}/hmac-key || (head -c 32 /dev/urandom > {{data_dir}}/hmac-key && chmod 600 {{data_dir}}/hmac-key && echo "generated hmac-key")
    @test -f {{data_dir}}/uri || (echo "{{uri}}" > {{data_dir}}/uri && echo "wrote uri")
    @echo "calendar data dir ready: {{data_dir}}"

# Regenerate OpenAPI / Swagger docs (relay API only)
swagger:
    go run github.com/swaggo/swag/cmd/swag@latest init -g cmd/server/main.go -o docs --parseDependency --parseInternal --exclude api/calendarserver

# Download and tidy Go module dependencies
tidy:
    go mod tidy

# Format, tidy, test, and regenerate swagger
check: tidy swagger test
