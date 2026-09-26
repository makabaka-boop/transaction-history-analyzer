package audit_test

import (
	"fmt"
	"math/rand"
	"reflect"
	"testing"

	"txcheck/audit"
)

// --- helpers to build logs concisely ---

func R(tx, key string) audit.Op { return audit.Op{Tx: tx, Op: audit.OpRead, Key: key} }
func W(tx, key string) audit.Op { return audit.Op{Tx: tx, Op: audit.OpWrite, Key: key} }
func C(tx string) audit.Op      { return audit.Op{Tx: tx, Op: audit.OpCommit} }
func A(tx string) audit.Op      { return audit.Op{Tx: tx, Op: audit.OpAbort} }

type wantSrc struct {
	op       int
	tx, key  string
	sourceTx string
	sourceOp int
}

type wantViol struct {
	ok bool
	op int // first violating op index, valid when !ok
	tx string
}

type caseDef struct {
	name    string
	txs     []string
	ops     []audit.Op
	sources []wantSrc
	edges   []audit.Edge
	order   []string // expected serial order when acyclic
	cycle   bool     // expect a cycle instead of a serial order
	rec     wantViol
	cas     wantViol
	str     wantViol
}

func handComputedCases() []caseDef {
	return []caseDef{
		{
			name: "serial chain: clean read of committed write",
			txs:  []string{"T1", "T2"},
			ops:  []audit.Op{W("T1", "x"), C("T1"), R("T2", "x"), C("T2")},
			sources: []wantSrc{
				{2, "T2", "x", "T1", 0},
			},
			edges: []audit.Edge{
				{From: "T1", To: "T2", Key: "x", Kind: "WR", Ops: [2]int{0, 2}},
			},
			order: []string{"T1", "T2"},
			rec:   wantViol{ok: true},
			cas:   wantViol{ok: true},
			str:   wantViol{ok: true},
		},
		{
			name: "dirty read: recoverable but not cascadeless or strict",
			txs:  []string{"T1", "T2"},
			ops:  []audit.Op{W("T1", "x"), R("T2", "x"), C("T1"), C("T2")},
			sources: []wantSrc{
				{1, "T2", "x", "T1", 0},
			},
			edges: []audit.Edge{
				{From: "T1", To: "T2", Key: "x", Kind: "WR", Ops: [2]int{0, 1}},
			},
			order: []string{"T1", "T2"},
			rec:   wantViol{ok: true},
			cas:   wantViol{ok: false, op: 1, tx: "T2"},
			str:   wantViol{ok: false, op: 1, tx: "T2"},
		},
		{
			name: "reader commits before its source: unrecoverable",
			txs:  []string{"T1", "T2"},
			ops:  []audit.Op{W("T1", "x"), R("T2", "x"), C("T2"), C("T1")},
			sources: []wantSrc{
				{1, "T2", "x", "T1", 0},
			},
			edges: []audit.Edge{
				{From: "T1", To: "T2", Key: "x", Kind: "WR", Ops: [2]int{0, 1}},
			},
			order: []string{"T1", "T2"},
			rec:   wantViol{ok: false, op: 2, tx: "T2"},
			cas:   wantViol{ok: false, op: 1, tx: "T2"},
			str:   wantViol{ok: false, op: 1, tx: "T2"},
		},
		{
			name: "source aborts, reader still commits: unrecoverable",
			txs:  []string{"T1", "T2"},
			ops:  []audit.Op{W("T1", "x"), R("T2", "x"), A("T1"), C("T2")},
			sources: []wantSrc{
				{1, "T2", "x", "T1", 0},
			},
			edges: []audit.Edge{
				{From: "T1", To: "T2", Key: "x", Kind: "WR", Ops: [2]int{0, 1}},
			},
			order: []string{"T1", "T2"},
			rec:   wantViol{ok: false, op: 3, tx: "T2"},
			cas:   wantViol{ok: false, op: 1, tx: "T2"},
			str:   wantViol{ok: false, op: 1, tx: "T2"},
		},
		{
			name: "source aborts and reader aborts too: recoverable",
			txs:  []string{"T1", "T2"},
			ops:  []audit.Op{W("T1", "x"), R("T2", "x"), A("T1"), A("T2")},
			sources: []wantSrc{
				{1, "T2", "x", "T1", 0},
			},
			edges: []audit.Edge{
				{From: "T1", To: "T2", Key: "x", Kind: "WR", Ops: [2]int{0, 1}},
			},
			order: []string{"T1", "T2"},
			rec:   wantViol{ok: true},
			cas:   wantViol{ok: false, op: 1, tx: "T2"},
			str:   wantViol{ok: false, op: 1, tx: "T2"},
		},
		{
			name: "aborted write stays the read source (dirty read not erased)",
			txs:  []string{"T1", "T2"},
			ops:  []audit.Op{W("T1", "x"), A("T1"), R("T2", "x"), C("T2")},
			sources: []wantSrc{
				{2, "T2", "x", "T1", 0}, // source is the aborted write, not the initial version
			},
			edges: []audit.Edge{
				{From: "T1", To: "T2", Key: "x", Kind: "WR", Ops: [2]int{0, 2}},
			},
			order: []string{"T1", "T2"},
			rec:   wantViol{ok: false, op: 3, tx: "T2"}, // source aborted but reader commits
			cas:   wantViol{ok: false, op: 2, tx: "T2"}, // source never committed
			str:   wantViol{ok: true},                   // writer already terminated at read time
		},
		{
			name: "overwrite of uncommitted write breaks strictness only",
			txs:  []string{"T1", "T2"},
			ops:  []audit.Op{W("T1", "x"), W("T2", "x"), C("T1"), C("T2")},
			edges: []audit.Edge{
				{From: "T1", To: "T2", Key: "x", Kind: "WW", Ops: [2]int{0, 1}},
			},
			order: []string{"T1", "T2"},
			rec:   wantViol{ok: true},
			cas:   wantViol{ok: true},
			str:   wantViol{ok: false, op: 1, tx: "T2"},
		},
		{
			name: "read-read is not a conflict",
			txs:  []string{"T1", "T2"},
			ops:  []audit.Op{R("T1", "x"), R("T2", "x"), C("T1"), C("T2")},
			sources: []wantSrc{
				{0, "T1", "x", "", -1},
				{1, "T2", "x", "", -1},
			},
			order: []string{"T1", "T2"},
			rec:   wantViol{ok: true},
			cas:   wantViol{ok: true},
			str:   wantViol{ok: true},
		},
		{
			name: "read of own uncommitted write is fine",
			txs:  []string{"T1", "T2"},
			ops:  []audit.Op{W("T1", "x"), R("T1", "x"), R("T2", "x"), C("T1"), C("T2")},
			sources: []wantSrc{
				{1, "T1", "x", "T1", 0},
				{2, "T2", "x", "T1", 0},
			},
			edges: []audit.Edge{
				{From: "T1", To: "T2", Key: "x", Kind: "WR", Ops: [2]int{0, 2}},
			},
			order: []string{"T1", "T2"},
			rec:   wantViol{ok: true},
			cas:   wantViol{ok: false, op: 2, tx: "T2"},
			str:   wantViol{ok: false, op: 2, tx: "T2"},
		},
		{
			name: "RW conflicts both ways make a real cycle",
			txs:  []string{"T1", "T2"},
			ops:  []audit.Op{R("T1", "x"), R("T2", "y"), W("T1", "y"), W("T2", "x"), C("T1"), C("T2")},
			sources: []wantSrc{
				{0, "T1", "x", "", -1},
				{1, "T2", "y", "", -1},
			},
			edges: []audit.Edge{
				{From: "T2", To: "T1", Key: "y", Kind: "RW", Ops: [2]int{1, 2}},
				{From: "T1", To: "T2", Key: "x", Kind: "RW", Ops: [2]int{0, 3}},
			},
			cycle: true,
			rec:   wantViol{ok: true},
			cas:   wantViol{ok: true},
			str:   wantViol{ok: true},
		},
		{
			name: "three-transaction cycle through WR and WW edges",
			txs:  []string{"T1", "T2", "T3"},
			ops: []audit.Op{
				W("T1", "x"), // 0
				R("T2", "x"), // 1: T1 -> T2 (WR x)
				W("T2", "y"), // 2
				R("T3", "y"), // 3: T2 -> T3 (WR y)
				W("T3", "z"), // 4
				R("T1", "z"), // 5: T3 -> T1 (WR z) closes the cycle
				C("T1"), C("T2"), C("T3"),
			},
			sources: []wantSrc{
				{1, "T2", "x", "T1", 0},
				{3, "T3", "y", "T2", 2},
				{5, "T1", "z", "T3", 4},
			},
			edges: []audit.Edge{
				{From: "T1", To: "T2", Key: "x", Kind: "WR", Ops: [2]int{0, 1}},
				{From: "T2", To: "T3", Key: "y", Kind: "WR", Ops: [2]int{2, 3}},
				{From: "T3", To: "T1", Key: "z", Kind: "WR", Ops: [2]int{4, 5}},
			},
			cycle: true,
			rec:   wantViol{ok: false, op: 6, tx: "T1"}, // T1 commits while T3 uncommitted
			cas:   wantViol{ok: false, op: 1, tx: "T2"},
			str:   wantViol{ok: false, op: 1, tx: "T2"},
		},
		{
			name: "serial order uses byte order of ids, not numeric order",
			txs:  []string{"T10", "T2", "T9"},
			ops:  []audit.Op{R("T9", "a"), C("T9"), R("T2", "b"), C("T2"), R("T10", "c"), C("T10")},
			sources: []wantSrc{
				{0, "T9", "a", "", -1},
				{2, "T2", "b", "", -1},
				{4, "T10", "c", "", -1},
			},
			order: []string{"T10", "T2", "T9"}, // bytewise: "T10" < "T2" < "T9"
			rec:   wantViol{ok: true},
			cas:   wantViol{ok: true},
			str:   wantViol{ok: true},
		},
		{
			name: "smallest topo order respects edges under byte-order tie-breaking",
			txs:  []string{"T1", "T2", "T3"},
			ops: []audit.Op{
				W("T3", "x"), // 0
				R("T1", "x"), // 1: T3 -> T1
				C("T3"),      // 2
				C("T1"),      // 3
				R("T2", "y"), // 4
				C("T2"),      // 5
			},
			sources: []wantSrc{
				{1, "T1", "x", "T3", 0},
				{4, "T2", "y", "", -1},
			},
			edges: []audit.Edge{
				{From: "T3", To: "T1", Key: "x", Kind: "WR", Ops: [2]int{0, 1}},
			},
			// T2 is free, T1 waits for T3: candidates T2,T3 -> T2 first,
			// then T3, then T1.
			order: []string{"T2", "T3", "T1"},
			rec:   wantViol{ok: true},
			cas:   wantViol{ok: false, op: 1, tx: "T1"},
			str:   wantViol{ok: false, op: 1, tx: "T1"},
		},
		{
			name: "committed source between write and read is cascadeless and strict",
			txs:  []string{"T1", "T2", "T3"},
			ops: []audit.Op{
				W("T1", "x"), // 0
				C("T1"),      // 1
				W("T2", "x"), // 2: overwrites committed value, allowed
				R("T3", "x"), // 3: reads T2's uncommitted write
				C("T2"),      // 4
				C("T3"),      // 5
			},
			sources: []wantSrc{
				{3, "T3", "x", "T2", 2},
			},
			edges: []audit.Edge{
				{From: "T1", To: "T2", Key: "x", Kind: "WW", Ops: [2]int{0, 2}},
				{From: "T1", To: "T3", Key: "x", Kind: "WR", Ops: [2]int{0, 3}},
				{From: "T2", To: "T3", Key: "x", Kind: "WR", Ops: [2]int{2, 3}},
			},
			order: []string{"T1", "T2", "T3"},
			rec:   wantViol{ok: true},
			cas:   wantViol{ok: false, op: 3, tx: "T3"},
			str:   wantViol{ok: false, op: 3, tx: "T3"},
		},
		{
			name: "first violation is reported, later ones are not",
			txs:  []string{"T1", "T2"},
			ops: []audit.Op{
				W("T1", "x"), // 0
				R("T2", "x"), // 1: first cascadeless + strict violation
				R("T2", "x"), // 2: also dirty, but not reported
				C("T1"),      // 3
				C("T2"),      // 4
			},
			sources: []wantSrc{
				{1, "T2", "x", "T1", 0},
				{2, "T2", "x", "T1", 0},
			},
			edges: []audit.Edge{
				{From: "T1", To: "T2", Key: "x", Kind: "WR", Ops: [2]int{0, 1}},
			},
			order: []string{"T1", "T2"},
			rec:   wantViol{ok: true},
			cas:   wantViol{ok: false, op: 1, tx: "T2"},
			str:   wantViol{ok: false, op: 1, tx: "T2"},
		},
	}
}

func TestHandComputedLogs(t *testing.T) {
	for _, tc := range handComputedCases() {
		t.Run(tc.name, func(t *testing.T) {
			rep, err := audit.Analyze(&audit.Log{Transactions: tc.txs, Operations: tc.ops})
			if err != nil {
				t.Fatalf("Analyze: %v", err)
			}

			var gotSrc []wantSrc
			for _, s := range rep.ReadSources {
				gotSrc = append(gotSrc, wantSrc{s.Op, s.Tx, s.Key, s.SourceTx, s.SourceOp})
			}
			if gotSrc == nil {
				gotSrc = []wantSrc{}
			}
			if tc.sources == nil {
				tc.sources = []wantSrc{}
			}
			if !reflect.DeepEqual(gotSrc, tc.sources) {
				t.Errorf("read sources:\n got %+v\nwant %+v", gotSrc, tc.sources)
			}

			if tc.edges == nil {
				tc.edges = []audit.Edge{}
			}
			if !reflect.DeepEqual(rep.ConflictEdges, tc.edges) {
				t.Errorf("conflict edges:\n got %+v\nwant %+v", rep.ConflictEdges, tc.edges)
			}

			if tc.cycle {
				if rep.Acyclic {
					t.Fatalf("expected a cycle, got serial order %v", rep.SerialOrder)
				}
				assertGenuineCycle(t, rep.ConflictEdges, rep.Cycle)
			} else {
				if !rep.Acyclic {
					t.Fatalf("expected acyclic graph, got cycle %v", rep.Cycle)
				}
				if !reflect.DeepEqual(rep.SerialOrder, tc.order) {
					t.Errorf("serial order: got %v, want %v", rep.SerialOrder, tc.order)
				}
			}

			checkProperty(t, "recoverable", rep.Recoverable, tc.rec)
			checkProperty(t, "cascadeless", rep.Cascadeless, tc.cas)
			checkProperty(t, "strict", rep.Strict, tc.str)
		})
	}
}

func checkProperty(t *testing.T, name string, got audit.CheckResult, want wantViol) {
	t.Helper()
	if got.OK != want.ok {
		t.Fatalf("%s: ok=%v, want %v (violation %+v)", name, got.OK, want.ok, got.FirstViolation)
	}
	if want.ok {
		return
	}
	if got.FirstViolation == nil {
		t.Fatalf("%s: missing first violation, want op %d by %s", name, want.op, want.tx)
	}
	if got.FirstViolation.Op != want.op || got.FirstViolation.Tx != want.tx {
		t.Errorf("%s: first violation = op %d by %s, want op %d by %s",
			name, got.FirstViolation.Op, got.FirstViolation.Tx, want.op, want.tx)
	}
	if got.FirstViolation.Reason == "" {
		t.Errorf("%s: violation has no reason", name)
	}
}

// assertGenuineCycle verifies the reported cycle is a real directed
// cycle: consecutive nodes (including last -> first) are graph edges.
func assertGenuineCycle(t *testing.T, edges []audit.Edge, cycle []string) {
	t.Helper()
	if len(cycle) < 3 { // at least A B A
		t.Fatalf("cycle too short: %v", cycle)
	}
	if cycle[0] != cycle[len(cycle)-1] {
		t.Fatalf("cycle %v does not return to its start", cycle)
	}
	edgeSet := map[[2]string]bool{}
	for _, e := range edges {
		edgeSet[[2]string{e.From, e.To}] = true
	}
	for i := 0; i+1 < len(cycle); i++ {
		if !edgeSet[[2]string{cycle[i], cycle[i+1]}] {
			t.Fatalf("cycle %v uses non-edge %s -> %s", cycle, cycle[i], cycle[i+1])
		}
	}
}

func TestValidation(t *testing.T) {
	valid := []audit.Op{W("T1", "x"), C("T1"), R("T2", "x"), C("T2")}
	cases := []struct {
		name string
		txs  []string
		ops  []audit.Op
	}{
		{"too few transactions", []string{"T1"}, []audit.Op{C("T1")}},
		{"too many transactions", []string{"1", "2", "3", "4", "5", "6", "7", "8", "9"}, nil},
		{"duplicate transaction id", []string{"T1", "T1"}, valid},
		{"empty transaction id", []string{"T1", ""}, valid},
		{"no operations", []string{"T1", "T2"}, nil},
		{"undeclared transaction", []string{"T1", "T2"}, []audit.Op{W("T1", "x"), C("T1"), C("T3")}},
		{"missing terminal op", []string{"T1", "T2"}, []audit.Op{W("T1", "x"), C("T1"), R("T2", "x")}},
		{"two terminal ops", []string{"T1", "T2"}, []audit.Op{C("T1"), C("T1"), C("T2")}},
		{"op after terminal", []string{"T1", "T2"}, []audit.Op{C("T1"), W("T1", "x"), C("T2")}},
		{"READ without key", []string{"T1", "T2"}, []audit.Op{R("T1", ""), C("T1"), C("T2")}},
		{"WRITE without key", []string{"T1", "T2"}, []audit.Op{W("T1", ""), C("T1"), C("T2")}},
		{"unknown op type", []string{"T1", "T2"}, []audit.Op{{Tx: "T1", Op: "SELECT"}, C("T1"), C("T2")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := audit.Analyze(&audit.Log{Transactions: tc.txs, Operations: tc.ops}); err == nil {
				t.Fatal("expected a validation error, got none")
			}
		})
	}

	t.Run("too many operations", func(t *testing.T) {
		ops := make([]audit.Op, 0, 501)
		for i := 0; i < 499; i++ {
			ops = append(ops, R("T1", "x"))
		}
		ops = append(ops, C("T1"), C("T2"))
		if _, err := audit.Analyze(&audit.Log{Transactions: []string{"T1", "T2"}, Operations: ops}); err == nil {
			t.Fatal("expected a validation error for 501 ops, got none")
		}
	})

	t.Run("500 operations accepted", func(t *testing.T) {
		ops := make([]audit.Op, 0, 500)
		for i := 0; i < 498; i++ {
			ops = append(ops, R("T1", "x"))
		}
		ops = append(ops, C("T1"), C("T2"))
		if _, err := audit.Analyze(&audit.Log{Transactions: []string{"T1", "T2"}, Operations: ops}); err != nil {
			t.Fatalf("unexpected error for 500 ops: %v", err)
		}
	})

	t.Run("8 transactions accepted", func(t *testing.T) {
		txs := []string{"1", "2", "3", "4", "5", "6", "7", "8"}
		var ops []audit.Op
		for _, tx := range txs {
			ops = append(ops, C(tx))
		}
		rep, err := audit.Analyze(&audit.Log{Transactions: txs, Operations: ops})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !rep.Acyclic || len(rep.SerialOrder) != 8 {
			t.Fatalf("expected serial order of all 8 txs, got %+v", rep)
		}
	})
}

// --- reference interpreter cross-check ---
//
// The functions below are an independent, deliberately brute-force
// reference implementation. Random valid logs are audited with both the
// real auditor and this reference, and the results must agree on read
// sources, graph edges, acyclicity, the serial order, and the three
// schedule properties.

func refSources(l *audit.Log) []wantSrc {
	var out []wantSrc
	for i, op := range l.Operations {
		if op.Op != audit.OpRead {
			continue
		}
		s := wantSrc{op: i, tx: op.Tx, key: op.Key, sourceOp: -1}
		for j := i - 1; j >= 0; j-- { // scan backwards for the most recent write
			if w := l.Operations[j]; w.Op == audit.OpWrite && w.Key == op.Key {
				s.sourceTx, s.sourceOp = w.Tx, j
				break
			}
		}
		out = append(out, s)
	}
	return out
}

func refEdgePairs(l *audit.Log) map[[2]string]bool {
	out := map[[2]string]bool{}
	for i := 0; i < len(l.Operations); i++ {
		a := l.Operations[i]
		if a.Op != audit.OpRead && a.Op != audit.OpWrite {
			continue
		}
		for j := i + 1; j < len(l.Operations); j++ {
			b := l.Operations[j]
			if b.Op != audit.OpRead && b.Op != audit.OpWrite {
				continue
			}
			if a.Tx == b.Tx || a.Key != b.Key {
				continue
			}
			if a.Op == audit.OpRead && b.Op == audit.OpRead {
				continue
			}
			out[[2]string{a.Tx, b.Tx}] = true
		}
	}
	return out
}

// refSerialOrder enumerates all permutations consistent with the
// conflict edges and returns the bytewise smallest, or nil if none.
func refSerialOrder(txs []string, edges map[[2]string]bool) []string {
	var best []string
	perm := make([]string, len(txs))
	used := make([]bool, len(txs))
	pos := make(map[string]int, len(txs))
	var visit func(k int)
	visit = func(k int) {
		if k == len(txs) {
			for e := range edges {
				if pos[e[0]] >= pos[e[1]] {
					return
				}
			}
			cand := append([]string{}, perm...)
			if best == nil || lessSeq(cand, best) {
				best = cand
			}
			return
		}
		for i, tx := range txs {
			if used[i] {
				continue
			}
			used[i] = true
			perm[k] = tx
			pos[tx] = k
			visit(k + 1)
			used[i] = false
		}
	}
	visit(0)
	return best
}

func lessSeq(a, b []string) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

func refTerminal(l *audit.Log) (commit, term map[string]int) {
	commit = map[string]int{}
	term = map[string]int{}
	for i, op := range l.Operations {
		switch op.Op {
		case audit.OpCommit:
			commit[op.Tx] = i
			term[op.Tx] = i
		case audit.OpAbort:
			term[op.Tx] = i
		}
	}
	return commit, term
}

// refRecoverable returns the index of the first COMMIT that precedes the
// commit of one of its reader's sources, or -1.
func refRecoverable(l *audit.Log) int {
	commit, _ := refTerminal(l)
	first := -1
	for _, s := range refSources(l) {
		if s.sourceTx == "" || s.sourceTx == s.tx {
			continue
		}
		rc, readerCommits := commit[s.tx]
		if !readerCommits {
			continue // reader aborts: always fine
		}
		sc, sourceCommits := commit[s.sourceTx]
		if !sourceCommits || sc > rc {
			if first == -1 || rc < first {
				first = rc
			}
		}
	}
	return first
}

// refCascadeless returns the index of the first READ whose source write
// was not committed at read time, or -1.
func refCascadeless(l *audit.Log) int {
	commit, _ := refTerminal(l)
	first := -1
	for _, s := range refSources(l) {
		if s.sourceTx == "" || s.sourceTx == s.tx {
			continue
		}
		sc, sourceCommits := commit[s.sourceTx]
		if !sourceCommits || sc > s.op {
			if first == -1 || s.op < first {
				first = s.op
			}
		}
	}
	return first
}

// refStrict returns the index of the first READ/WRITE touching a key
// whose most recent writer is another, still-active transaction, or -1.
func refStrict(l *audit.Log) int {
	_, term := refTerminal(l)
	for i, op := range l.Operations {
		if op.Op != audit.OpRead && op.Op != audit.OpWrite {
			continue
		}
		for j := i - 1; j >= 0; j-- {
			w := l.Operations[j]
			if w.Op != audit.OpWrite || w.Key != op.Key {
				continue
			}
			if w.Tx != op.Tx {
				if t, terminated := term[w.Tx]; !terminated || t > i {
					return i
				}
			}
			break // only the most recent write matters
		}
	}
	return -1
}

func randomLog(r *rand.Rand) *audit.Log {
	idPool := []string{"A", "B", "T1", "T10", "T2", "a1", "z", "Q9"}
	r.Shuffle(len(idPool), func(i, j int) { idPool[i], idPool[j] = idPool[j], idPool[i] })
	ntx := 2 + r.Intn(7) // 2..8
	txs := append([]string{}, idPool[:ntx]...)
	keys := []string{"x", "y", "z"}

	seqs := make([][]audit.Op, ntx)
	for i, tx := range txs {
		n := r.Intn(4) // 0..3 data ops
		for k := 0; k < n; k++ {
			key := keys[r.Intn(len(keys))]
			if r.Intn(2) == 0 {
				seqs[i] = append(seqs[i], R(tx, key))
			} else {
				seqs[i] = append(seqs[i], W(tx, key))
			}
		}
		if r.Intn(4) == 0 {
			seqs[i] = append(seqs[i], A(tx))
		} else {
			seqs[i] = append(seqs[i], C(tx))
		}
	}
	// Random interleaving that preserves each transaction's op order.
	var ops []audit.Op
	pos := make([]int, ntx)
	remaining := 0
	for _, s := range seqs {
		remaining += len(s)
	}
	for remaining > 0 {
		var pick int
		for {
			pick = r.Intn(ntx)
			if pos[pick] < len(seqs[pick]) {
				break
			}
		}
		ops = append(ops, seqs[pick][pos[pick]])
		pos[pick]++
		remaining--
	}
	return &audit.Log{Transactions: txs, Operations: ops}
}

func TestReferenceCrossCheck(t *testing.T) {
	r := rand.New(rand.NewSource(20260926))
	for iter := 0; iter < 3000; iter++ {
		l := randomLog(r)
		rep, err := audit.Analyze(l)
		if err != nil {
			t.Fatalf("iter %d: random log rejected: %v\n%+v", iter, err, l)
		}
		ctx := fmt.Sprintf("iter %d log %+v", iter, l)

		// Read sources.
		var gotSrc []wantSrc
		for _, s := range rep.ReadSources {
			gotSrc = append(gotSrc, wantSrc{s.Op, s.Tx, s.Key, s.SourceTx, s.SourceOp})
		}
		if wantSrc := refSources(l); !reflect.DeepEqual(gotSrc, wantSrc) {
			t.Fatalf("%s\nread sources: got %+v, want %+v", ctx, gotSrc, wantSrc)
		}

		// Conflict edges (as a set of pairs).
		wantEdges := refEdgePairs(l)
		gotEdges := map[[2]string]bool{}
		for _, e := range rep.ConflictEdges {
			pair := [2]string{e.From, e.To}
			if gotEdges[pair] {
				t.Fatalf("%s\nduplicate edge %v", ctx, pair)
			}
			gotEdges[pair] = true
			if e.Ops[0] >= e.Ops[1] {
				t.Fatalf("%s\nedge %+v has ops out of order", ctx, e)
			}
		}
		if !reflect.DeepEqual(gotEdges, wantEdges) {
			t.Fatalf("%s\nedges: got %v, want %v", ctx, gotEdges, wantEdges)
		}

		// Serializability and serial order.
		wantOrder := refSerialOrder(l.Transactions, wantEdges)
		if rep.Acyclic != (wantOrder != nil) {
			t.Fatalf("%s\nacyclic=%v but reference order is %v", ctx, rep.Acyclic, wantOrder)
		}
		if rep.Acyclic {
			if !reflect.DeepEqual(rep.SerialOrder, wantOrder) {
				t.Fatalf("%s\nserial order: got %v, want %v", ctx, rep.SerialOrder, wantOrder)
			}
		} else {
			assertGenuineCycle(t, rep.ConflictEdges, rep.Cycle)
		}

		// The three properties.
		checkRefProperty(t, ctx, "recoverable", rep.Recoverable, refRecoverable(l))
		checkRefProperty(t, ctx, "cascadeless", rep.Cascadeless, refCascadeless(l))
		checkRefProperty(t, ctx, "strict", rep.Strict, refStrict(l))
	}
}

func checkRefProperty(t *testing.T, ctx, name string, got audit.CheckResult, wantFirstOp int) {
	t.Helper()
	if got.OK != (wantFirstOp == -1) {
		t.Fatalf("%s\n%s: ok=%v but reference first violation op=%d", ctx, name, got.OK, wantFirstOp)
	}
	if wantFirstOp != -1 {
		if got.FirstViolation == nil || got.FirstViolation.Op != wantFirstOp {
			t.Fatalf("%s\n%s: first violation=%+v, want op %d", ctx, name, got.FirstViolation, wantFirstOp)
		}
	}
}
