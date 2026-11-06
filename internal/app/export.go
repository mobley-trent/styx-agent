package app

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/mobley-trent/styx-agent/internal/engagementstate"
	"github.com/mobley-trent/styx-agent/internal/findingsexport"
)

// emitFindingsExport writes the run's export to --out, if one was asked for,
// and prints the line that makes an omission visible (§2). A failed export
// fails the run: a pipeline that asked for one never receives a half-written
// set (docs/findings-export.md §5).
func (h *Harness) emitFindingsExport(printer *headlessPrinter) error {
	if h.outDir == "" {
		return nil
	}
	reported, omitted, err := h.writeFindingsExport()
	if err != nil {
		printer.refusal("export failed: " + err.Error())
		return fmt.Errorf("write findings export: %w", err)
	}
	printer.write(fmt.Sprintf("styx: export %d findings · %d omitted", reported, omitted))
	return nil
}

// writeFindingsExport renders the current engagement state and writes the three
// artifacts. A safe-mode run has no store: it exports a valid, empty document
// with a null engagement rather than nothing at all (§5).
func (h *Harness) writeFindingsExport() (reported, omitted int, err error) {
	snapshot, engagement := h.findingsSnapshot()

	files, err := findingsexport.Render(snapshot, engagement, h.Version)
	if err != nil {
		return 0, 0, err
	}
	reported, omitted = findingsexport.Counts(snapshot)
	if err := writeExportSet(h.outDir, files); err != nil {
		return reported, omitted, err
	}
	return reported, omitted, nil
}

// findingsSnapshot reads the state the export renders and the gate evaluates,
// so both read one snapshot (§8.2, §8.5). A safe-mode run has no store: its set
// is empty rather than fabricated (§8.4).
func (h *Harness) findingsSnapshot() (engagementstate.Snapshot, string) {
	h.mu.Lock()
	store := h.state
	h.mu.Unlock()
	if store == nil {
		return engagementstate.Snapshot{}, ""
	}
	return store.Snapshot(), store.Engagement()
}

// writeExportSet writes all three artifacts or none. Each is written to a
// temporary file in the destination directory and renamed into place; a
// failure part-way removes the set, so the destination never holds a partial
// export (§5).
func writeExportSet(dir string, files findingsexport.Files) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}

	set := []struct {
		name string
		data []byte
	}{
		{findingsexport.JSONName, files.JSON},
		{findingsexport.CSVName, files.CSV},
		{findingsexport.SARIFName, files.SARIF},
	}

	temps := make([]string, 0, len(set))
	removeTemps := func() {
		for _, tmp := range temps {
			_ = os.Remove(tmp)
		}
	}
	for _, f := range set {
		tmp, err := os.CreateTemp(dir, f.name+".tmp-*")
		if err != nil {
			removeTemps()
			return err
		}
		temps = append(temps, tmp.Name())
		if err := tmp.Chmod(0o644); err != nil {
			_ = tmp.Close()
			removeTemps()
			return err
		}
		if _, err := tmp.Write(f.data); err != nil {
			_ = tmp.Close()
			removeTemps()
			return err
		}
		if err := tmp.Close(); err != nil {
			removeTemps()
			return err
		}
	}

	for i, f := range set {
		if err := os.Rename(temps[i], filepath.Join(dir, f.name)); err != nil {
			removeTemps()
			removeExportedSet(dir)
			return err
		}
	}
	return nil
}

// removeExportedSet removes the three artifacts, so a failure mid-rename leaves
// no partial set behind.
func removeExportedSet(dir string) {
	for _, name := range []string{
		findingsexport.JSONName, findingsexport.CSVName, findingsexport.SARIFName,
	} {
		_ = os.Remove(filepath.Join(dir, name))
	}
}
