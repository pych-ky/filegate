package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	updatecontrol "filegate.local/filegate/internal/update"
	"flag"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"io"
	"net/url"
	"os"
	"path/filepath"
)

type request struct {
	Operation string               `json:"op"`
	Clock     *updatecontrol.Clock `json:"clock,omitempty"`
	Library   string               `json:"library_sha256,omitempty"`
	UpdateID  string               `json:"update_id,omitempty"`
	Report    json.RawMessage      `json:"report,omitempty"`
	Reason    string               `json:"reason,omitempty"`
	Cleaned   bool                 `json:"cleaned,omitempty"`
}

func run() error {
	database := flag.String("fixture-db", "", "isolated synthetic update store")
	flag.Parse()
	if !filepath.IsAbs(*database) {
		return errors.New("absolute fixture database required")
	}
	data, err := io.ReadAll(io.LimitReader(os.Stdin, (1<<20)+16385))
	if err != nil || len(data) > (1<<20)+16384 {
		return errors.New("request limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var r request
	if decoder.Decode(&r) != nil || decoder.Decode(new(any)) != io.EOF {
		return errors.New("invalid fixture request")
	}
	info, err := os.Lstat(*database)
	created := errors.Is(err, os.ErrNotExist)
	if err != nil && !created {
		return err
	}
	if created {
		if r.Operation != "initialize" {
			return errors.New("explicit fixture initialization required")
		}
		f, err := os.OpenFile(*database, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if err != nil {
			return err
		}
		f.Close()
	} else if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return errors.New("private fixture database required")
	}
	u := url.URL{Scheme: "file", Path: *database}
	q := u.Query()
	q.Set("_foreign_keys", "on")
	q.Set("_txlock", "immediate")
	q.Set("_busy_timeout", "5000")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite3", u.String())
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if !created {
		var marker string
		if db.QueryRow("SELECT value FROM filegate_update_fixture WHERE id=1").Scan(&marker) != nil || marker != "synthetic-no-product-adoption" {
			return errors.New("not an isolated fixture store")
		}
	}
	if _, err = db.Exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA fullfsync=ON; PRAGMA checkpoint_fullfsync=ON;"); err != nil {
		return err
	}
	if created {
		if _, err = db.Exec("CREATE TABLE filegate_update_fixture(id INTEGER PRIMARY KEY,value TEXT); INSERT INTO filegate_update_fixture VALUES(1,'synthetic-no-product-adoption')"); err != nil {
			return err
		}
	}
	store, err := updatecontrol.Open(db)
	if err != nil {
		return err
	}
	var now updatecontrol.Clock
	clockKind := "synthetic_clock"
	if r.Clock != nil {
		now = *r.Clock
	} else {
		now, err = updatecontrol.ReadClock()
		if err != nil {
			return err
		}
		clockKind = "host_continuous_clock"
	}
	output := map[string]any{"fixture_only": true, "network_requests": 0, "product_adoption_enabled": false, "clock_kind": clockKind}
	var control updatecontrol.Control
	switch r.Operation {
	case "initialize":
		control, err = store.Initialize(updatecontrol.Binding{LibrarySHA256: r.Library, FixtureOnly: true}, now)
	case "read":
		control, err = store.Read(now)
	case "start":
		var attempt updatecontrol.Attempt
		control, attempt, err = store.Begin(r.UpdateID, now)
		output["attempt"] = attempt
	case "restore":
		var restored updatecontrol.RestoreRequest
		restored, err = store.Restore(r.UpdateID, now)
		output["restore_request"] = restored
	case "final":
		control, err = store.Final(r.UpdateID, r.Report, now)
	case "stop":
		control, err = store.Stop(r.UpdateID, r.Reason, now)
	case "stopped":
		control, err = store.Stopped(r.UpdateID, r.Cleaned, now)
	case "recover":
		control, err = store.Recover(now)
	case "deadline":
		err = store.CheckDeadline(r.UpdateID, now)
	case "attempt":
		var attempt updatecontrol.Attempt
		attempt, err = store.Attempt(r.UpdateID)
		output["attempt"] = attempt
	case "seed_freshness_fixture":
		control, err = store.Read(now)
		if err == nil && !control.Binding.FixtureOnly {
			return errors.New("fixture binding required")
		}
		if err == nil {
			control.Definition = &updatecontrol.DefinitionSet{UpdateID: "synthetic_definition", Generation: control.Generation, Confirmed: now,
				ManifestSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
			data, _ := json.Marshal(control)
			_, err = db.ExecContext(context.Background(), "UPDATE update_control SET data=? WHERE scope=?", data, updatecontrol.Scope)
		}
	default:
		return errors.New("unknown fixture operation")
	}
	if err != nil {
		var domain updatecontrol.Error
		if !errors.As(err, &domain) {
			return err
		}
		output["reason"] = err.Error()
	} else {
		output["reason"] = nil
	}
	current, readErr := store.Read(now)
	if readErr == nil {
		control = current
	} else if err == nil {
		output["reason"] = readErr.Error()
	}
	output["control"], output["definition_fresh"] = control, updatecontrol.Fresh(control, now)
	return json.NewEncoder(os.Stdout).Encode(output)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
