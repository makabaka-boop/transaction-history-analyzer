// Package audit analyzes an interleaved transaction operation log and
// reports what the final database state alone cannot tell you:
// where every READ got its value from, the conflict graph between
// transactions, and whether the schedule was recoverable, cascadeless
// and strict.
//
// Log model: 2-8 transactions, up to 500 ordered READ/WRITE/COMMIT/ABORT
// operations. Every transaction has exactly one terminal op (COMMIT or
// ABORT) and no ops after it.
//
// Semantics:
//   - The source of a READ is the most recent prior WRITE on the same key
//     in log order (by any transaction), or the initial version if there
//     is none. An aborted write still counts as the source: aborting a
//     write does not erase a dirty read that already happened.
//   - A conflict is a pair of ops on the same key by different
//     transactions where at least one is a WRITE (RW, WR or WW). The
//     earlier op's transaction points to the later one's, building a
//     directed graph in log order.
//   - Recoverable: a reader must not COMMIT before the transaction whose
//     write it read, and if that source aborts the reader must abort too.
//   - Cascadeless: a READ may only come from a write that was already
//     committed at read time.
//   - Strict: a READ or WRITE must not touch a key whose most recent
//     write belongs to another, still-active (uncommitted, not aborted)
//     transaction.
package audit

import "fmt"

// OpType is one of READ, WRITE, COMMIT, ABORT.
type OpType string

const (
	OpRead   OpType = "READ"
	OpWrite  OpType = "WRITE"
	OpCommit OpType = "COMMIT"
	OpAbort  OpType = "ABORT"
)

// Op is a single logged operation. Key is required for READ/WRITE and
// ignored for COMMIT/ABORT. Value is optional and informational only.
type Op struct {
	Tx    string `json:"tx"`
	Op    OpType `json:"op"`
	Key   string `json:"key,omitempty"`
	Value *int64 `json:"value,omitempty"`
}

// Log is the auditor input: the declared transactions plus the ordered
// operation log.
type Log struct {
	Transactions []string `json:"transactions"`
	Operations   []Op     `json:"operations"`
}

const (
	minTransactions = 2
	maxTransactions = 8
	maxOperations   = 500
)

// Validate checks the structural rules of the log.
func (l *Log) Validate() error {
	if len(l.Transactions) < minTransactions || len(l.Transactions) > maxTransactions {
		return fmt.Errorf("transactions: need %d-%d distinct ids, got %d",
			minTransactions, maxTransactions, len(l.Transactions))
	}
	declared := make(map[string]bool, len(l.Transactions))
	for _, tx := range l.Transactions {
		if tx == "" {
			return fmt.Errorf("transactions: empty transaction id")
		}
		if declared[tx] {
			return fmt.Errorf("transactions: duplicate id %q", tx)
		}
		declared[tx] = true
	}
	if len(l.Operations) == 0 || len(l.Operations) > maxOperations {
		return fmt.Errorf("operations: need 1-%d ops, got %d", maxOperations, len(l.Operations))
	}
	terminals := make(map[string]int, len(l.Transactions)) // tx -> index of its terminal op
	for i, op := range l.Operations {
		if !declared[op.Tx] {
			return fmt.Errorf("operations[%d]: undeclared transaction %q", i, op.Tx)
		}
		if t, ok := terminals[op.Tx]; ok {
			return fmt.Errorf("operations[%d]: transaction %q operates after its terminal op at index %d", i, op.Tx, t)
		}
		switch op.Op {
		case OpRead, OpWrite:
			if op.Key == "" {
				return fmt.Errorf("operations[%d]: %s requires a key", i, op.Op)
			}
		case OpCommit, OpAbort:
			terminals[op.Tx] = i
		default:
			return fmt.Errorf("operations[%d]: unknown op %q (want READ, WRITE, COMMIT or ABORT)", i, op.Op)
		}
	}
	for _, tx := range l.Transactions {
		if _, ok := terminals[tx]; !ok {
			return fmt.Errorf("transaction %q has no terminal COMMIT/ABORT op", tx)
		}
	}
	return nil
}

// ReadSource records where one READ op got its value from. SourceOp is
// the index of the source WRITE, or -1 for the initial version (in which
// case SourceTx is empty).
type ReadSource struct {
	Op       int    `json:"op"`
	Tx       string `json:"tx"`
	Key      string `json:"key"`
	SourceTx string `json:"sourceTx,omitempty"`
	SourceOp int    `json:"sourceOp"`
}

// Edge is one directed conflict edge. Kind is "RW", "WR" or "WW"; Ops
// holds the indexes of the two conflicting operations (earliest such
// pair for this edge).
type Edge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Key  string `json:"key"`
	Kind string `json:"kind"`
	Ops  [2]int `json:"ops"`
}

// Violation pinpoints the first log operation that breaks a property.
type Violation struct {
	Op     int    `json:"op"`
	Tx     string `json:"tx"`
	Reason string `json:"reason"`
}

// CheckResult is the verdict for one schedule property.
type CheckResult struct {
	OK             bool       `json:"ok"`
	FirstViolation *Violation `json:"firstViolation,omitempty"`
}

// Report is the full audit result. Operation indexes are 0-based
// positions in the input log.
type Report struct {
	Transactions  []string     `json:"transactions"`
	ReadSources   []ReadSource `json:"readSources"`
	ConflictEdges []Edge       `json:"conflictEdges"`
	Acyclic       bool         `json:"acyclic"`
	SerialOrder   []string     `json:"serialOrder,omitempty"`
	Cycle         []string     `json:"cycle,omitempty"`
	Recoverable   CheckResult  `json:"recoverable"`
	Cascadeless   CheckResult  `json:"cascadeless"`
	Strict        CheckResult  `json:"strict"`
}

// Analyze validates the log and audits it.
func Analyze(l *Log) (*Report, error) {
	if err := l.Validate(); err != nil {
		return nil, err
	}
	ops := l.Operations
	rep := &Report{
		Transactions:  l.Transactions,
		ReadSources:   []ReadSource{},
		ConflictEdges: []Edge{},
	}

	committed := map[string]bool{}  // tx committed before the current op
	terminated := map[string]bool{} // tx committed or aborted before the current op
	lastWrite := map[string]int{}   // key -> index of most recent WRITE
	priorOps := map[string][]int{}  // key -> indexes of prior READ/WRITE ops

	type readDep struct {
		sourceTx         string
		readOp, sourceOp int
	}
	readsByTx := map[string][]readDep{}
	edgeSeen := map[[2]string]bool{}

	for i, op := range ops {
		switch op.Op {
		case OpRead, OpWrite:
			// Conflict edges: every earlier conflicting op points here.
			for _, j := range priorOps[op.Key] {
				p := ops[j]
				if p.Tx == op.Tx || (p.Op == OpRead && op.Op == OpRead) {
					continue
				}
				pair := [2]string{p.Tx, op.Tx}
				if !edgeSeen[pair] {
					edgeSeen[pair] = true
					rep.ConflictEdges = append(rep.ConflictEdges, Edge{
						From: p.Tx, To: op.Tx, Key: op.Key,
						Kind: string(p.Op[0]) + string(op.Op[0]),
						Ops:  [2]int{j, i},
					})
				}
			}
			// Strict: the key's most recent writer must not still be active.
			if j, ok := lastWrite[op.Key]; ok {
				if w := ops[j]; w.Tx != op.Tx && !terminated[w.Tx] && rep.Strict.FirstViolation == nil {
					rep.Strict.FirstViolation = &Violation{
						Op: i, Tx: op.Tx,
						Reason: fmt.Sprintf("%s of key %q touches uncommitted write by %s (op %d)",
							op.Op, op.Key, w.Tx, j),
					}
				}
			}
			if op.Op == OpWrite {
				lastWrite[op.Key] = i
			} else {
				src := ReadSource{Op: i, Tx: op.Tx, Key: op.Key, SourceOp: -1}
				if j, ok := lastWrite[op.Key]; ok {
					src.SourceTx, src.SourceOp = ops[j].Tx, j
				}
				rep.ReadSources = append(rep.ReadSources, src)
				if src.SourceTx != "" && src.SourceTx != op.Tx {
					readsByTx[op.Tx] = append(readsByTx[op.Tx],
						readDep{src.SourceTx, i, src.SourceOp})
					// Cascadeless: the source write must be committed by now.
					if !committed[src.SourceTx] && rep.Cascadeless.FirstViolation == nil {
						rep.Cascadeless.FirstViolation = &Violation{
							Op: i, Tx: op.Tx,
							Reason: fmt.Sprintf("READ of key %q comes from uncommitted write by %s (op %d)",
								op.Key, src.SourceTx, src.SourceOp),
						}
					}
				}
			}
			priorOps[op.Key] = append(priorOps[op.Key], i)
		case OpCommit:
			// Recoverable: every transaction we read from must have
			// committed before us (a source that aborts forces us to
			// abort, so committing is a violation either way).
			for _, d := range readsByTx[op.Tx] {
				if !committed[d.sourceTx] {
					if rep.Recoverable.FirstViolation == nil {
						rep.Recoverable.FirstViolation = &Violation{
							Op: i, Tx: op.Tx,
							Reason: fmt.Sprintf("COMMIT precedes commit of %s, whose write (op %d) was read at op %d",
								d.sourceTx, d.sourceOp, d.readOp),
						}
					}
					break
				}
			}
			committed[op.Tx] = true
			terminated[op.Tx] = true
		case OpAbort:
			terminated[op.Tx] = true
		}
	}
	rep.Recoverable.OK = rep.Recoverable.FirstViolation == nil
	rep.Cascadeless.OK = rep.Cascadeless.FirstViolation == nil
	rep.Strict.OK = rep.Strict.FirstViolation == nil

	order, acyclic := topoSort(l.Transactions, rep.ConflictEdges)
	rep.Acyclic = acyclic
	if acyclic {
		rep.SerialOrder = order
	} else {
		rep.Cycle = findCycle(l.Transactions, rep.ConflictEdges)
	}
	return rep, nil
}

// topoSort returns the lexicographically smallest topological order of
// the conflict graph, comparing transaction ids bytewise, or reports
// that the graph has a cycle.
func topoSort(nodes []string, edges []Edge) ([]string, bool) {
	indeg := make(map[string]int, len(nodes))
	adj := map[string][]string{}
	for _, n := range nodes {
		indeg[n] = 0
	}
	for _, e := range edges {
		adj[e.From] = append(adj[e.From], e.To)
		indeg[e.To]++
	}
	done := make(map[string]bool, len(nodes))
	order := make([]string, 0, len(nodes))
	for len(order) < len(nodes) {
		pick := ""
		for _, n := range nodes {
			if done[n] || indeg[n] != 0 {
				continue
			}
			if pick == "" || n < pick { // bytewise id comparison
				pick = n
			}
		}
		if pick == "" {
			return nil, false
		}
		done[pick] = true
		order = append(order, pick)
		for _, m := range adj[pick] {
			indeg[m]--
		}
	}
	return order, true
}

// findCycle returns a real directed cycle as a node sequence that starts
// and ends with the same transaction. It must only be called on a
// cyclic graph.
func findCycle(nodes []string, edges []Edge) []string {
	adj := map[string][]string{}
	for _, e := range edges {
		adj[e.From] = append(adj[e.From], e.To)
	}
	const (
		white = iota // unvisited
		gray         // on the current DFS stack
		black        // fully explored
	)
	color := make(map[string]int, len(nodes))
	var stack []string
	var cycle []string
	var dfs func(u string) bool
	dfs = func(u string) bool {
		color[u] = gray
		stack = append(stack, u)
		for _, v := range adj[u] {
			switch color[v] {
			case gray:
				start := 0
				for i, n := range stack {
					if n == v {
						start = i
						break
					}
				}
				cycle = append(append([]string{}, stack[start:]...), v)
				return true
			case white:
				if dfs(v) {
					return true
				}
			}
		}
		stack = stack[:len(stack)-1]
		color[u] = black
		return false
	}
	for _, n := range nodes {
		if color[n] == white && dfs(n) {
			return cycle
		}
	}
	return nil
}
