package verification

import (
	"os"
	"path/filepath"
	"regexp"
)

// release-unknown-abort requests the ordinary abort while the release-unknown state holds: the request must stay PENDING
// with resources held across a same-key resend and a restart; cleanup restores the same temp and the saved request settles.
func init() { Register("release-unknown-abort", runReleaseUnknownAbort) }

func runReleaseUnknownAbort(h *Harness) {
	releaseUnknownCase(h, releaseUnknownCaseSpec{"filegate-release-unknown-abort", "abort requested during an unresolved INTENT with neither final nor temp: the reviewed prepublish broker stops before the rename and the release temp is moved to a private holding directory; the ordinary abort, a same-key resend and a restart must keep RECOVERY_REQUIRED with the abort PENDING and resources held; cleanup restores the same temp and the saved abort settles at startup; existing genuine PASS job, dedicated state and private destination", "filegate-release-unknown-abort-plan"}, releaseUnknownPendingAbort)
}

// releaseUnknownSave fixes one raw record of the unknown state before any cleanup.
func releaseUnknownSave(h *Harness, name string, status int, response Object, release string) Object {
	rows := deliveryRowSnapshot(h)
	WriteJSON(filepath.Join(h.Out, name), Object{"http_status": status, "response": response, "ledger": releaseBoundaryLedger(h, release), "release_rows": QueryObjects(h, "SELECT data FROM releases WHERE id=?", release), "rows": rows})
	return rows
}

func releaseUnknownPendingAbort(h *Harness, u *releaseUnknownRun) {
	pending := func(receipt Object) bool {
		return Str(receipt, "release_id") == u.release && Str(receipt, "state") == "RECOVERY_REQUIRED" && Contains(receipt["reason_codes"], "PUBLICATION_UNKNOWN") && Str(receipt, "publication_status") == "UNKNOWN" && Get(receipt, "publication_confirmed") == false && Bool(receipt, "abort_requested") && Str(receipt, "abort_outcome") == "PENDING" && Get(receipt, "success") == false && Get(receipt, "resources_finalized") == false
	}
	// Unresolved single INTENT, one authorization, held resources, no final or temp, unchanged held file.
	holding := func(label string) bool {
		ledger := releaseBoundaryLedger(h, u.release)
		attempts := List(ledger, "attempts")
		return len(attempts) == 1 && Str(attempts[0], "state") == "INTENT" && releaseBoundaryCount(h, "SELECT count(*) FROM release_authorizations WHERE release_id=?", u.release) == 1 && Int(ledger, "release_pins") == 1 && Int(ledger, "release_reservations") == 1 && Int(ledger, "open_releases") == u.openBefore+1 && !Exists(u.final) && !Exists(u.temp) && Equal(releaseUnknownIdentity(h, label, u.held), u.tempIdentity) && Equal(releaseBoundaryEntries(u.extra.Destination.Path), []string{".filegate-staging"}) && len(releaseBoundaryEntries(u.staging)) == 0
	}
	resend := func() (int, Object, Object) {
		status, response := h.Request("POST", "/v1/jobs/"+u.extra.JobID+"/release", Object{"destination_id": u.extra.Destination.ID}, map[string]string{"Idempotency-Key": u.extra.ReleaseKey}, nil)
		if ErrorCode(response) != "" {
			return status, response, Map(response, "error", "receipt")
		}
		return status, response, response
	}
	// The reused job's original object, located only by the object_id of its receipt: owned, regular and single-link,
	// read with no-follow up to the recorded size.
	job := Map(h.Record, "job_before")
	objectID := Str(job, "input_receipt", "object_id")
	objectPath := filepath.Join(h.Data, "objects", objectID)
	objectFile := func(label string) Object {
		body := deliveryRead(objectPath, Int(job, "input_receipt", "byte_size"))
		identity, err := releaseUnknownStat(objectPath)
		Must(err)
		identity["sha256"] = Digest(body)
		h.Record[label] = identity
		return identity
	}
	objectBefore := objectFile("original_object_before_abort")
	h.Check("original_object_fixed_before_abort", regexp.MustCompile(`^object_[0-9a-f]{32}$`).MatchString(objectID) && Get(u.unknownRows, "objects", "rows", objectID) != nil && Bool(objectBefore, "regular") && Int(objectBefore, "nlink") == 1 && Int(objectBefore, "uid") == int64(os.Geteuid()) && Int(objectBefore, "size") == Int(job, "input_receipt", "byte_size") && Str(objectBefore, "sha256") == Str(job, "input_receipt", "sha256"))

	// Scenario 4: the ordinary abort during the unknown state is only recorded as PENDING; nothing is settled.
	status, requested := h.Request("POST", "/v1/releases/"+u.release+"/abort", nil, nil, nil)
	abortRows := releaseUnknownSave(h, "abort-pending.json", status, requested, u.release)
	stored := QueryObjects(h, "SELECT data FROM releases WHERE id=?", u.release)
	requestedAt := ""
	if len(stored) == 1 {
		requestedAt = Str(stored[0], "abort_requested_at")
	}
	h.Check("abort_pending_keeps_recovery_required", status == 202 && pending(requested) && requestedAt != "" && Str(stored[0], "no_publication_at") == "")
	h.Check("abort_pending_intent_unresolved_resources_held", holding("held_identity_after_abort"))
	// Of the recorded tables, only this release's row changes; every other table and release row stays the same.
	others := len(Map(abortRows, "releases", "rows")) == len(Map(u.unknownRows, "releases", "rows")) && !Equal(Get(abortRows, "releases", "rows", u.release), Get(u.unknownRows, "releases", "rows", u.release))
	for table, value := range abortRows {
		if table != "releases" {
			others = others && Equal(value, u.unknownRows[table])
		}
	}
	for id, row := range Map(abortRows, "releases", "rows") {
		if id != u.release {
			others = others && Equal(row, Get(u.unknownRows, "releases", "rows", id))
		}
	}
	h.Check("abort_pending_changes_only_this_release_row", others)

	// Scenario 5: the same-key resend neither copies, publishes nor settles; the request stays PENDING.
	status, resent, resentReceipt := resend()
	resendRows := releaseUnknownSave(h, "abort-resend.json", status, resent, u.release)
	h.Check("abort_resend_keeps_pending", Bool(resentReceipt, "replayed") && pending(resentReceipt))
	h.Check("abort_resend_changes_no_rows_or_files", Equal(resendRows, abortRows) && holding("held_identity_after_abort_resend"))

	// Scenario 6: after a normal stop, a restart without the temp keeps the saved request PENDING.
	h.Stop(false)
	h.Start(u.serve...)
	status, restarted := h.Request("GET", "/v1/releases/"+u.release, nil, nil, nil)
	restartRows := releaseUnknownSave(h, "abort-restart.json", status, restarted, u.release)
	stored = QueryObjects(h, "SELECT data FROM releases WHERE id=?", u.release)
	h.Check("abort_restart_keeps_pending", status == 200 && pending(restarted) && len(stored) == 1 && Str(stored[0], "abort_requested_at") == requestedAt)
	// Only the release tables are compared across the restart; startup work may touch the others.
	same := true
	for _, table := range []string{"releases", "release_publication_attempts", "release_authorizations", "resource_pins", "release_reservations"} {
		same = same && Equal(restartRows[table], resendRows[table])
	}
	h.Check("abort_restart_keeps_release_rows_and_files", same && holding("held_identity_after_abort_restart"))
	h.Stop(false)

	// Cleanup (recorded apart from the pending-abort results): restore the same temp; the saved request settles at startup.
	cleanup := Object{}
	h.Record["cleanup"] = cleanup
	h.Check("cleanup_restore_target_absent", !Exists(u.temp) && Equal(releaseUnknownIdentity(h, "held_identity_before_restore", u.held), u.tempIdentity))
	Must(releaseUnknownMove(u.extra.HoldingPath, u.tempName, u.staging, u.tempName))
	h.Record["temp_in_holding"] = false
	restored := releaseUnknownIdentity(h, "temp_identity_after_restore", u.temp)
	h.Check("cleanup_temp_restored_same_identity", Equal(restored, u.tempIdentity) && !Exists(u.held) && len(releaseBoundaryEntries(u.extra.HoldingPath)) == 0)
	h.Start(u.serve...)
	status, settled := h.Request("GET", "/v1/releases/"+u.release, nil, nil, nil)
	ledger := releaseBoundaryLedger(h, u.release)
	stored = QueryObjects(h, "SELECT data FROM releases WHERE id=?", u.release)
	settledRows := deliveryRowSnapshot(h)
	cleanup["after_restore_restart"] = Object{"http_status": status, "receipt": settled, "ledger": ledger, "release_rows": stored}
	attempts := List(ledger, "attempts")
	h.Check("cleanup_restart_settles_saved_abort", status == 200 && Str(settled, "state") == "ABORTED" && Str(settled, "abort_outcome") == "ABORTED" && Bool(settled, "abort_requested") && Contains(settled["reason_codes"], "RELEASE_ABORTED") && Str(settled, "publication_status") == "NOT_PUBLISHED" && Get(settled, "publication_confirmed") == false && Get(settled, "success") == false && Bool(settled, "resources_finalized") && len(attempts) == 1 && Str(attempts[0], "state") == "NO_PUBLICATION_PROVEN" && Str(attempts[0], "evidence") == "same_boot_unchanged_unconsumed_exclusive_temp" && len(stored) == 1 && Int(stored[0], "generation") == 1 && Str(stored[0], "abort_requested_at") == requestedAt && Str(stored[0], "no_publication_at") != "" && Str(stored[0], "cleanup_confirmed_at") != "" && releaseBoundaryCount(h, "SELECT count(*) FROM release_authorizations WHERE release_id=?", u.release) == 1 && Int(ledger, "release_pins") == 0 && Int(ledger, "release_reservations") == 0 && Int(ledger, "open_releases") == u.openBefore)
	h.Check("cleanup_temp_removed_final_never_created", !Exists(u.temp) && !Exists(u.final) && Equal(releaseBoundaryEntries(u.extra.Destination.Path), []string{".filegate-staging"}) && len(releaseBoundaryEntries(u.staging)) == 0 && len(releaseBoundaryEntries(u.extra.HoldingPath)) == 0)
	h.Check("cleanup_original_object_kept", Equal(settledRows["objects"], u.unknownRows["objects"]) && Equal(objectFile("original_object_after_settle"), objectBefore))

	// A terminal same-key resend returns the original receipt with RELEASE_ABORTED and changes no recorded row.
	status, again, againReceipt := resend()
	afterRows := deliveryRowSnapshot(h)
	cleanup["terminal_resend"] = Object{"http_status": status, "response": again}
	original, returned := Object{}, Object{}
	for key, value := range settled {
		if key != "replayed" {
			original[key] = value
		}
	}
	for key, value := range againReceipt {
		if key != "replayed" {
			returned[key] = value
		}
	}
	h.Check("terminal_resend_release_aborted_unchanged", status == 409 && ErrorCode(again) == "RELEASE_ABORTED" && Bool(againReceipt, "replayed") && Equal(returned, original) && Equal(afterRows, settledRows) && !Exists(u.final) && len(releaseBoundaryEntries(u.staging)) == 0)
}
