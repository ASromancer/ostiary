// Run: node internal/ui/testdata/check_test.mjs  (not part of go test)
import { readFileSync } from "node:fs";
import assert from "node:assert";
const src = readFileSync(new URL("../static/app.js", import.meta.url), "utf8");
const blk = src.match(/\/\/ ---- check:begin[\s\S]*?\/\/ ---- check:end/)[0];
const { checkTip, checkWhy } = new Function(blk + "\n; return { checkTip, checkWhy };")();
assert.strictEqual(checkTip(null), "Chưa kiểm tra kết nối");
const at = new Date(2026, 10, 17, 14, 2).toISOString();
assert.strictEqual(checkTip({ At: at, OK: true, Stages: [] }), "Kiểm tra lúc 14:02: kết nối tốt");
const bad = { At: at, OK: false, Stages: [{ stage: "tcp", ok: true }, { stage: "hostkey", ok: true }, { stage: "auth", ok: false, code: "auth", err: "raw" }] };
assert.strictEqual(checkTip(bad), "Kiểm tra lúc 14:02: auth lỗi — sai user, key hoặc mật khẩu?");
assert.strictEqual(checkWhy({ code: "noauth", err: "vault đang khóa" }), "vault đang khóa");
assert.strictEqual(checkWhy({ code: "weird" }), "lỗi");
console.log("check ok");
