// Command txcheck audits an interleaved transaction operation log.
//
// Usage:
//
//	txcheck [-i file] [-compact]
//
// Input is JSON on stdin or in -i file; the audit report is JSON on
// stdout. Exit code is 0 when the log is valid (findings are reported
// in the JSON, not via exit code) and 1 for unreadable or invalid input.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"txcheck/audit"
)

func main() {
	in := flag.String("i", "", "input JSON file (default: stdin)")
	compact := flag.Bool("compact", false, "emit compact single-line JSON")
	flag.Parse()

	var data []byte
	var err error
	if *in == "" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(*in)
	}
	if err != nil {
		fatal("cannot read input: %v", err)
	}

	var log audit.Log
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&log); err != nil {
		fatal("invalid JSON: %v", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		fatal("invalid JSON: trailing data after top-level object")
	}

	rep, err := audit.Analyze(&log)
	if err != nil {
		fatal("invalid log: %v", err)
	}

	var out []byte
	if *compact {
		out, err = json.Marshal(rep)
	} else {
		out, err = json.MarshalIndent(rep, "", "  ")
	}
	if err != nil {
		fatal("cannot encode report: %v", err)
	}
	fmt.Println(string(out))
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "txcheck: "+format+"\n", args...)
	os.Exit(1)
}
