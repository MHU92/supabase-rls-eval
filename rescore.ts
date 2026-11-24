// Scores the saved answers of a run directory again, e.g. after a fix in the harness. No model calls.
// Usage: deno run --allow-run=psql --allow-read --allow-write=runs --allow-env rescore.ts runs/<dir>

import { type Row, writeReport } from "./report.ts";
import { score } from "./score.ts";

const dir = Deno.args[0];
const old: Row[] = JSON.parse(await Deno.readTextFile(`${dir}/results.json`));
const rows: Row[] = [];
for (const r of old) {
  const sql = await Deno.readTextFile(`${dir}/${r.task}.${r.condition}.${r.run}.sql`);
  rows.push({ ...r, score: await score(r.task, sql) });
}
const [, model] = dir.match(/T\d{4}-([^/]+)\/?$/) ?? [];
await writeReport(dir, rows, model ?? "?", Math.max(...rows.map((r) => r.run)));
console.log(await Deno.readTextFile(`${dir}/results.md`));
