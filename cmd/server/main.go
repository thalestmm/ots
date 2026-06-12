// Copyright (C) 2025 Thales Meier
//
// This file is part of OTS.

package main

import (
	"context"
	"crypto/rand"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	httpSwagger "github.com/swaggo/http-swagger"

	"github.com/thalestmm/ots/api/server"
	"github.com/thalestmm/ots/internal/bitcoin"
	"github.com/thalestmm/ots/internal/calendar"
	"github.com/thalestmm/ots/internal/stamper"

	_ "github.com/thalestmm/ots/docs"
)

const version = "0.2.0"

// @title           OTS API
// @version         0.2.0
// @description     OpenTimestamps calendar server and SDK (Go), with Bitcoin anchoring.
// @termsOfService  https://github.com/thalestmm/ots

// @contact.name   OTS
// @contact.url    https://github.com/thalestmm/ots

// @license.name  LGPL-3.0
// @license.url   https://www.gnu.org/licenses/lgpl-3.0.html

// @host      localhost:14788
// @BasePath  /

// @accept      application/json
// @accept      application/octet-stream
// @produce     application/json
// @produce     application/octet-stream
func main() {
	addr := flag.String("addr", ":14788", "listen address")
	calendarURI := flag.String("calendar-uri", "http://127.0.0.1:14788", "calendar URI embedded in pending attestations (persisted on first boot)")
	dataDir := flag.String("data-dir", defaultDataDir(), `calendar data directory; "memory" runs without persistence (dev only)`)
	logJSON := flag.Bool("log-json", false, "emit structured JSON logs")

	btcHost := flag.String("btc-rpc-host", "", "Bitcoin Core RPC host:port; empty disables the stamper")
	btcUser := flag.String("btc-rpc-user", "", "Bitcoin Core RPC username")
	btcPass := flag.String("btc-rpc-pass", "", "Bitcoin Core RPC password")
	btcNetwork := flag.String("btc-network", "mainnet", "bitcoin network: mainnet | testnet | regtest")
	minConf := flag.Int64("btc-min-confirmations", 6, "confirmations required before a proof is considered anchored")
	minTxInterval := flag.Duration("btc-min-tx-interval", 6*time.Hour, "minimum interval between anchor transactions")
	maxFeeBTC := flag.Float64("btc-max-fee", 0.001, "maximum anchor transaction fee in BTC")
	maxPending := flag.Int("max-pending", 100000, "maximum pending commitments in the stamper pool")
	flag.Parse()

	logLevel := slog.LevelInfo
	var logHandler slog.Handler = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})
	if *logJSON {
		logHandler = slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})
	}
	log := slog.New(logHandler)
	slog.SetDefault(log)

	// Storage: persistent data-dir by default, in-memory for dev.
	var (
		store   calendar.Storage
		journal *calendar.Journal
		dd      *calendar.DataDir
		hmacKey []byte
		uri     = *calendarURI
	)
	if *dataDir == "memory" {
		log.Warn("running with in-memory storage; commitments will NOT survive restart")
		store = calendar.NewMemoryStore()
		hmacKey = make([]byte, 32)
		if _, err := rand.Read(hmacKey); err != nil {
			log.Error("generate hmac key", "err", err)
			os.Exit(1)
		}
	} else {
		var err error
		dd, err = calendar.OpenDataDir(*dataDir, *calendarURI)
		if err != nil {
			log.Error("open data dir", "dir", *dataDir, "err", err)
			os.Exit(1)
		}
		defer dd.Close()
		store = dd.Store
		journal = dd.Journal
		hmacKey = dd.HMACKey
		uri = dd.URI
		log.Info("data dir opened", "dir", *dataDir, "uri", uri, "journal_entries", journal.Len())
	}

	cal := calendar.NewService(uri, hmacKey, store)
	if journal != nil {
		cal.WithJournal(journal)
	}
	agg := calendar.NewAggregator(cal, time.Second)

	h := server.NewHandler(agg, cal, version)

	// Bitcoin stamper (optional).
	var (
		btc        *bitcoin.Client
		st         *stamper.Stamper
		stamperCtx context.Context
		stopStamp  context.CancelFunc = func() {}
	)
	if *btcHost != "" {
		var err error
		btc, err = bitcoin.NewClient(bitcoin.Config{
			Host: *btcHost, User: *btcUser, Pass: *btcPass, Network: *btcNetwork,
		})
		if err != nil {
			log.Error("bitcoin rpc client", "err", err)
			os.Exit(1)
		}
		if err := btc.CheckNetwork(); err != nil {
			log.Error("bitcoin network check", "err", err)
			os.Exit(1)
		}
		if journal == nil {
			log.Error("the stamper requires a persistent --data-dir (journal); refusing to anchor from memory")
			os.Exit(1)
		}
		maxFee, err := btcutil.NewAmount(*maxFeeBTC)
		if err != nil {
			log.Error("invalid --btc-max-fee", "err", err)
			os.Exit(1)
		}
		cfg := stamper.Config{
			MinConfirmations: *minConf,
			MinTxInterval:    *minTxInterval,
			MaxFee:           maxFee,
			MaxPending:       *maxPending,
			Tick:             5 * time.Second,
		}
		st = stamper.New(journal, store, btc, cfg, log)
		if err := st.Recover(); err != nil {
			log.Error("stamper recovery", "err", err)
			os.Exit(1)
		}
		stamperCtx, stopStamp = context.WithCancel(context.Background())
		go st.Run(stamperCtx)
		log.Info("bitcoin stamper enabled",
			"network", *btcNetwork, "min_confirmations", *minConf,
			"min_tx_interval", *minTxInterval, "max_fee_btc", *maxFeeBTC)
	} else {
		log.Warn("stamper disabled (no --btc-rpc-host); proofs will stay pending and verification cannot confirm Bitcoin attestations")
	}
	h.WithBitcoin(btc, st)

	mux := http.NewServeMux()
	h.Register(mux)
	mux.Handle("/swagger/", httpSwagger.Handler(
		httpSwagger.URL("doc.json"),
	))

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Info("ots server listening", "addr", *addr)
		log.Info("swagger ui", "url", "http://"+trimAddr(*addr)+"/swagger/index.html")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("server error", "err", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	// Graceful shutdown: stop accepting requests, drain the aggregator so
	// every accepted digest reaches the journal, then stop the stamper and
	// close the data dir (deferred).
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Error("http shutdown", "err", err)
	}
	agg.Close()
	stopStamp()
	_ = stamperCtx
	log.Info("shutdown complete")
}

func defaultDataDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".otsd/calendar"
	}
	return filepath.Join(home, ".otsd", "calendar")
}

func trimAddr(addr string) string {
	if addr[0] == ':' {
		return "127.0.0.1" + addr
	}
	return addr
}
