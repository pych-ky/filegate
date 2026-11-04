package update

type runtimePythonInventory struct {
	Method               string   `json:"method"`
	RemovedPaths         []string `json:"removed_paths"`
	RemainingPythonPaths []string `json:"remaining_python_paths"`
	InspectedInodes      int      `json:"inspected_inodes"`
	InventorySHA256      string   `json:"inventory_sha256"`
}

func (r *runtimePythonInventory) valid() bool {
	return r != nil && r.Method == "bounded_recursive_debugfs_inode_inventory" && r.RemainingPythonPaths != nil && len(r.RemainingPythonPaths) == 0 &&
		r.InspectedInodes > 0 && r.InspectedInodes <= 100000 && len(r.RemovedPaths) <= 100000 && digestPattern.MatchString(r.InventorySHA256)
}

type runtimeInitramfsInspection struct {
	Entries                  int  `json:"entries"`
	AllUIDGIDZero            bool `json:"all_uid_gid_zero"`
	AllLinksOne              bool `json:"all_links_one"`
	RequiredBootFilesPresent bool `json:"required_boot_files_present"`
	GzipCRCReadToEnd         bool `json:"gzip_CRC_read_to_end"`
	PythonRuntimeAbsent      bool `json:"python_runtime_absent"`
}

func (r *runtimeInitramfsInspection) valid() bool {
	return r != nil && r.Entries > 0 && r.Entries <= 100000 && r.AllUIDGIDZero && r.AllLinksOne && r.RequiredBootFilesPresent && r.GzipCRCReadToEnd && r.PythonRuntimeAbsent
}
