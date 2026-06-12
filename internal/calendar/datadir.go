// Copyright (C) 2025 Thales Meier
//
// This file is part of OTS.

package calendar

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DataDir holds the persistent on-disk state of a calendar instance:
//
//	<dir>/journal        append-only commitment journal
//	<dir>/db/ots.db      bbolt commitment store
//	<dir>/uri            stable public calendar URL
//	<dir>/hmac-key       32-byte secret, generated on first boot only
//	<dir>/donation_addr  optional, for status page
type DataDir struct {
	Path         string
	URI          string
	HMACKey      []byte
	DonationAddr string
	Journal      *Journal
	Store        *BoltStore
}

// OpenDataDir initializes (first boot) or opens an existing calendar data
// directory. defaultURI is only used when no uri file exists yet; afterwards
// the persisted value wins so already-issued pending attestations stay
// resolvable.
func OpenDataDir(dir, defaultURI string) (*DataDir, error) {
	if err := os.MkdirAll(filepath.Join(dir, "db"), 0o700); err != nil {
		return nil, err
	}

	hmacKey, err := loadOrCreateHMACKey(filepath.Join(dir, "hmac-key"))
	if err != nil {
		return nil, err
	}

	uri, err := loadOrCreateText(filepath.Join(dir, "uri"), defaultURI)
	if err != nil {
		return nil, err
	}
	if uri == "" {
		return nil, fmt.Errorf("calendar URI required: pass --calendar-uri on first boot or write %s", filepath.Join(dir, "uri"))
	}

	donation, _ := os.ReadFile(filepath.Join(dir, "donation_addr"))

	journal, err := OpenJournal(filepath.Join(dir, "journal"))
	if err != nil {
		return nil, err
	}
	store, err := OpenBoltStore(filepath.Join(dir, "db", "ots.db"))
	if err != nil {
		journal.Close()
		return nil, err
	}

	return &DataDir{
		Path:         dir,
		URI:          uri,
		HMACKey:      hmacKey,
		DonationAddr: strings.TrimSpace(string(donation)),
		Journal:      journal,
		Store:        store,
	}, nil
}

func (d *DataDir) Close() error {
	err := d.Journal.Close()
	if cerr := d.Store.Close(); err == nil {
		err = cerr
	}
	return err
}

func loadOrCreateHMACKey(path string) ([]byte, error) {
	key, err := os.ReadFile(path)
	if err == nil {
		if len(key) != 32 {
			return nil, fmt.Errorf("hmac-key at %s must be exactly 32 bytes, got %d", path, len(key))
		}
		return key, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	key = make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := writeFileSync(path, key, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

func loadOrCreateText(path, def string) (string, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		return strings.TrimSpace(string(data)), nil
	}
	if !os.IsNotExist(err) {
		return "", err
	}
	if def == "" {
		return "", nil
	}
	if err := writeFileSync(path, []byte(def+"\n"), 0o644); err != nil {
		return "", err
	}
	return def, nil
}

func writeFileSync(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
