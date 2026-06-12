// Copyright (C) 2025 Thales Meier
//
// This file is part of OTS.

package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	httpSwagger "github.com/swaggo/http-swagger"

	"github.com/thalestmm/ots/api/server"
	"github.com/thalestmm/ots/internal/bitcoin"
	"github.com/thalestmm/ots/pkg/ots"

	_ "github.com/thalestmm/ots/docs"
)

const version = "0.3.0"

// @title           OTS Relay API
// @version         0.3.0
// @description     OpenTimestamps relay API: stamps and upgrades proofs via public upstream calendars.
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
	calendarsFlag := flag.String("calendars", "", "comma-separated upstream calendar URLs (default: public mainnet calendars)")
	calendarTimeout := flag.Duration("calendar-timeout", 30*time.Second, "per-upstream HTTP timeout")
	logJSON := flag.Bool("log-json", false, "emit structured JSON logs")

	btcHost := flag.String("btc-rpc-host", "", "Bitcoin Core RPC host:port for verify; empty disables confirmed verify")
	btcUser := flag.String("btc-rpc-user", "", "Bitcoin Core RPC username")
	btcPass := flag.String("btc-rpc-pass", "", "Bitcoin Core RPC password")
	btcNetwork := flag.String("btc-network", "mainnet", "bitcoin network: mainnet | testnet | regtest")
	flag.Parse()

	logLevel := slog.LevelInfo
	var logHandler slog.Handler = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})
	if *logJSON {
		logHandler = slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})
	}
	log := slog.New(logHandler)
	slog.SetDefault(log)

	urls := parseCalendars(*calendarsFlag)
	pool, err := ots.NewPoolWithTimeout(urls, *calendarTimeout)
	if err != nil {
		log.Error("create calendar pool", "err", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *calendarTimeout)
	defer cancel()
	reachable := 0
	for _, u := range pool.URLs() {
		if err := pool.Ping(ctx, u); err != nil {
			log.Warn("upstream calendar unreachable", "url", u, "err", err)
			continue
		}
		reachable++
		log.Info("upstream calendar ok", "url", u)
	}
	if reachable == 0 {
		log.Error("no upstream calendars reachable; refusing to start")
		os.Exit(1)
	}

	h := server.NewHandler(pool, version)

	if *btcHost != "" {
		btc, err := bitcoin.NewClient(bitcoin.Config{
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
		h.WithBitcoin(btc)
		log.Info("bitcoin verify enabled", "network", *btcNetwork)
	} else {
		log.Warn("bitcoin verify disabled; /api/v1/verify cannot return valid=true for confirmed proofs")
	}

	mux := http.NewServeMux()
	h.Register(mux)
	mux.Handle("/swagger/", httpSwagger.Handler(
		httpSwagger.URL("doc.json"),
	))

	srv := &http.Server{
		Addr:              *addr,
		Handler:           server.RequestLogging(log, mux),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Info("ots relay listening", "addr", *addr, "calendars", len(pool.URLs()))
		log.Info("swagger ui", "url", "http://"+trimAddr(*addr)+"/swagger/index.html")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("server error", "err", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error("http shutdown", "err", err)
	}
	log.Info("shutdown complete")
}

func parseCalendars(flagVal string) []string {
	if env := strings.TrimSpace(os.Getenv("OTS_CALENDARS")); env != "" {
		flagVal = env
	}
	if strings.TrimSpace(flagVal) == "" {
		return ots.DefaultCalendars
	}
	var urls []string
	for _, part := range strings.Split(flagVal, ",") {
		if u := strings.TrimSpace(part); u != "" {
			urls = append(urls, u)
		}
	}
	return urls
}

func trimAddr(addr string) string {
	if len(addr) > 0 && addr[0] == ':' {
		return "127.0.0.1" + addr
	}
	return addr
}
