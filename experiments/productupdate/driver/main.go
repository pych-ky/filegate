package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	updatecontrol "filegate.local/filegate/internal/update"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/sys/unix"
)

func run() error {
	state := flag.String("state", "", "separate fixture state directory")
	manifest := flag.String("manifest", "", "fixed NIC-free runtime manifest")
	id := flag.String("update-id", "", "fixture update identity")
	recovering := flag.Bool("recover", false, "resume owned cleanup without starting a VM")
	flag.Parse()
	if !filepath.IsAbs(*state) || filepath.Clean(*state) != *state || *id == "" {
		return errors.New("invalid fixture scope")
	}
	created := false
	if _, err := os.Lstat(*state); errors.Is(err, os.ErrNotExist) && !*recovering {
		if err = os.Mkdir(*state, 0700); err != nil {
			return err
		}
		created = true
	}
	info, err := os.Lstat(*state)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return errors.New("private fixture directory required")
	}
	scope := filepath.Join(*state, "fixture-scope.txt")
	if created {
		file, err := os.OpenFile(scope, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		_, err = file.WriteString("filegate-update-fixture-v1\n")
		if err == nil {
			err = file.Sync()
		}
		file.Close()
		if err != nil {
			return err
		}
	} else {
		info, err := os.Lstat(scope)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			return errors.New("fixture scope marker missing")
		}
		body, err := os.ReadFile(scope)
		if err != nil || string(body) != "filegate-update-fixture-v1\n" {
			return errors.New("fixture scope marker changed")
		}
	}
	lock, err := os.OpenFile(filepath.Join(*state, "owner.lock"), os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		return errors.New("fixture owner active")
	}
	m, err := updatecontrol.ReadRuntimeManifest(*manifest)
	if err != nil {
		return err
	}
	database := filepath.Join(*state, "fixture.sqlite")
	if created {
		file, err := os.OpenFile(database, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if err != nil {
			return err
		}
		file.Close()
	}
	dbInfo, err := os.Lstat(database)
	if err != nil || !dbInfo.Mode().IsRegular() || dbInfo.Mode().Perm() != 0600 {
		return errors.New("private fixture database required")
	}
	u := url.URL{Scheme: "file", Path: database}
	query := u.Query()
	query.Set("_foreign_keys", "on")
	query.Set("_txlock", "immediate")
	query.Set("_busy_timeout", "5000")
	u.RawQuery = query.Encode()
	db, err := sql.Open("sqlite3", u.String())
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if created {
		if _, err = db.Exec("CREATE TABLE filegate_update_fixture(id INTEGER PRIMARY KEY,value TEXT); INSERT INTO filegate_update_fixture VALUES(1,'synthetic-no-product-adoption')"); err != nil {
			return err
		}
	}
	var marker string
	if db.QueryRow("SELECT value FROM filegate_update_fixture WHERE id=1").Scan(&marker) != nil || marker != "synthetic-no-product-adoption" {
		return errors.New("fixture marker missing")
	}
	if _, err = db.Exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA fullfsync=ON; PRAGMA checkpoint_fullfsync=ON;"); err != nil {
		return err
	}
	store, err := updatecontrol.Open(db)
	if err != nil {
		return err
	}
	now, err := updatecontrol.ReadClock()
	if err != nil {
		return err
	}
	if created {
		if _, err = store.Initialize(updatecontrol.Binding{LibrarySHA256: m.LibrarySHA256, FixtureOnly: true}, now); err != nil {
			return err
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	directory := filepath.Join(*state, "runtime-"+*id)
	var result updatecontrol.RuntimeResult
	if *recovering {
		result, err = store.RecoverFixture(*manifest, directory, *id)
	} else {
		result, err = store.RunFixture(ctx, *manifest, directory, *id)
	}
	operationErr := err
	now, err = updatecontrol.ReadClock()
	if err != nil {
		return err
	}
	control, err := store.Read(now)
	if err != nil {
		return err
	}
	attempt, attemptErr := store.Attempt(*id)
	value := map[string]any{"fixture_only": true, "product_adoption_enabled": false, "network_enabled": false,
		"runtime": result, "control": control, "attempt": attempt, "definition_fresh": updatecontrol.Fresh(control, now)}
	if operationErr != nil {
		value["error"] = operationErr.Error()
	}
	if attemptErr != nil {
		value["attempt_error"] = attemptErr.Error()
	}
	if err = json.NewEncoder(os.Stdout).Encode(value); err != nil {
		return err
	}
	return operationErr
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
