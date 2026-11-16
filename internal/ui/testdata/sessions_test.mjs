// Run: node internal/ui/testdata/sessions_test.mjs  (not part of go test)
import { readFileSync } from "node:fs";
import assert from "node:assert";
const src = readFileSync(new URL("../static/app.js", import.meta.url), "utf8");
const blk = src.match(/\/\/ ---- sessions:begin[\s\S]*?\/\/ ---- sessions:end/)[0];
const { groupSessions } = new Function(blk + "\n; return { groupSessions };")();
const at = (min, o) => Object.assign({ time: new Date(Date.UTC(2026, 10, 16, 12, 0) - min * 60000).toISOString(), agent: "claude", repo: "/r/a", decision: "allow" }, o);
// newest first
const g = groupSessions([at(0), at(10), at(25), at(70), at(80, { agent: "codex" }), at(90, { agent: "codex", repo: "", cwd: "/x" }), at(95, { agent: "codex", repo: "", cwd: "/x" })]);
assert.deepStrictEqual(g.map((x) => x.entries.length), [3, 1, 1, 2]); // 45 min gap splits; agent and project split
assert.strictEqual(g[3].proj, "/x"); // cwd when there is no repo
assert.strictEqual(g[0].newest - g[0].oldest, 25 * 60000);
assert.deepStrictEqual(groupSessions([]), []);
console.log("sessions ok");
