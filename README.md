# txcheck — 事务日志审计器

一段数据库操作日志可能最终写出正确数值，却仍包含读未提交、先于来源事务提交或冲突环；只看最终状态无法解释这些风险。`txcheck` 是一个 Go 命令行审计器：读取一份交错的事务操作日志（JSON），独立报告每个 READ 的来源、事务冲突图（及串行顺序或真实有向环），以及可恢复性、无级联读、严格执行三项性质的首个违反操作。

## 输入格式

从 stdin（或 `-i 文件`）读取一个 JSON 对象：

```json
{
  "transactions": ["T1", "T2"],
  "operations": [
    {"tx": "T1", "op": "WRITE", "key": "x", "value": 42},
    {"tx": "T2", "op": "READ", "key": "x"},
    {"tx": "T1", "op": "COMMIT"},
    {"tx": "T2", "op": "COMMIT"}
  ]
}
```

结构约束（不满足则报错退出，退出码 1）：

- 2～8 个不同的事务 id；
- 至多 500 个按序操作，类型为 `READ`、`WRITE`、`COMMIT`、`ABORT`；
- `READ`/`WRITE` 必须带 `key`；`value` 可选，仅作记录；
- 每个事务恰有一个终止操作（`COMMIT` 或 `ABORT`），终止后不得再操作；
- 操作只能引用已声明的事务。

## 判定语义

- **读来源**：每个 `READ` 的来源是同一键上此前最近一次 `WRITE`（不论来自哪个事务、后来是否撤销），否则为初始版本（`sourceOp: -1`）。写入被撤销也不能抹去曾经发生的脏读——被撤销的写仍然是后续读的来源。
- **冲突图**：不同事务对同一键的冲突操作（`RW`、`WR`、`WW`，即至少一方为写）按日志顺序构成有向边，早操作的事务指向晚操作的事务。
- **串行顺序**：图无环时给出 id 字节序最小（按字节比较事务 id 的字典序最小拓扑序）的串行顺序 `serialOrder`；有环时给出真实有向环 `cycle`（首尾相同的事务序列，每对相邻节点都是真实边）。
- **可恢复（recoverable）**：读者不能先于其来源事务提交；来源若撤销，读者也须撤销。违反时报告读者的 `COMMIT` 操作。
- **无级联读（cascadeless）**：只读已提交的写入——读发生时来源写必须已提交。违反时报告该 `READ`。
- **严格执行（strict）**：不读写他人未提交的写入——`READ`/`WRITE` 发生时，该键最近一次写必须不属于其他仍未终止（未提交也未撤销）的事务。违反时报告该读写操作。

三项性质各自独立判定，分别报告首个违反操作。

## 输出格式

JSON 报告写入 stdout（操作下标从 0 开始）：

```json
{
  "transactions": ["T1", "T2"],
  "readSources": [{"op": 1, "tx": "T2", "key": "x", "sourceTx": "T1", "sourceOp": 0}],
  "conflictEdges": [{"from": "T1", "to": "T2", "key": "x", "kind": "WR", "ops": [0, 1]}],
  "acyclic": true,
  "serialOrder": ["T1", "T2"],
  "recoverable": {"ok": true},
  "cascadeless": {"ok": false, "firstViolation": {"op": 1, "tx": "T2", "reason": "..."}},
  "strict": {"ok": false, "firstViolation": {"op": 1, "tx": "T2", "reason": "..."}}
}
```

有环时 `serialOrder` 省略、输出 `cycle`；无环时反之。审计发现不影响退出码：日志合法即退出 0，结论都在报告里。

## 运行

本地（需要 Go 1.23+）：

```sh
go run ./cmd/txcheck < examples/dirty-read.json
go run ./cmd/txcheck -i examples/conflict-cycle.json -compact
```

Compose 的 `txcheck` 服务（批处理式：stdin 进、stdout 出）：

```sh
docker compose build
docker compose run --rm -T txcheck < examples/dirty-read.json
docker compose run --rm -T -v "$PWD/examples:/data:ro" txcheck -i /data/conflict-cycle.json
```

## 测试

```sh
go test ./...
```

`audit/audit_test.go` 包含两类测试：

- **手算小日志**：针对读来源、图边、串行顺序/环、三项性质逐条核对预期（含脏读、来源撤销、覆盖未提交写、RW 冲突环、id 字节序等边界情形）；
- **参考解释器对拍**：测试文件内另写了一套独立的暴力参考实现（倒序扫描求读来源、全对比较求边、枚举全排列求最小串行序、独立的三性质判定），用固定种子的随机日志生成器产出 3000 份合法日志，与审计器逐项比对读来源、图边、无环性、串行顺序及三项性质的首个违反位置；有环时校验报告的环是真实有向环。

## 示例

`examples/` 下的小日志覆盖了典型情形：

| 文件 | 情形 |
| --- | --- |
| `serializable-ok.json` | 干净的串行链，三项性质全通过 |
| `dirty-read.json` | 脏读：可恢复但违反无级联读与严格执行 |
| `unrecoverable-commit.json` | 读者先于来源提交：违反可恢复性 |
| `aborted-source-commit.json` | 来源撤销而读者仍提交：违反可恢复性 |
| `conflict-cycle.json` | 双向 RW 冲突构成真实有向环 |
