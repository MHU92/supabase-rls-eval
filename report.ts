// Writes results.json and results.md for one run directory.
// A run counts as "safe" when no check found a leak and as "correct" when every check passed.

import type { Score } from "./score.ts";
import { TASKS } from "./tasks.ts";

export type Row = { task: string; condition: string; run: number; score: Score; costUsd: number };
const CONDITIONS = ["baseline", "with-guide"];

export async function writeReport(dir: string, rows: Row[], model: string, runs: number) {
  await Deno.writeTextFile(`${dir}/results.json`, JSON.stringify(rows, null, 1));
  const share = (r: Row[], f: (x: Row) => boolean) => `${r.filter(f).length}/${r.length}`;
  const safe = (x: Row) => x.score.leaks === 0;
  const correct = (x: Row) => x.score.passed === x.score.total;

  const lines = [
    `# Results: ${model}, ${runs} run(s) per task and condition`,
    "",
    "| Task | Condition | Safe | Correct | Migration failed |",
    "|---|---|---|---|---|",
  ];
  for (const t of TASKS) {
    for (const c of CONDITIONS) {
      const r = rows.filter((x) => x.task === t.id && x.condition === c);
      lines.push(`| ${t.title} | ${c} | ${share(r, safe)} | ${share(r, correct)} | ${share(r, (x) => !!x.score.migrationError)} |`);
    }
  }
  lines.push("");
  for (const c of CONDITIONS) {
    const r = rows.filter((x) => x.condition === c);
    const cost = r.reduce((a, x) => a + x.costUsd, 0);
    lines.push(`- **${c}:** ${share(r, safe)} safe, ${share(r, correct)} correct, ${share(r, (x) => !!x.score.migrationError)} migrations failed, cost $${cost.toFixed(2)}`);
  }

  lines.push("", "## What went wrong", "");
  for (const x of rows) {
    const s = x.score;
    if (s.migrationError) lines.push(`- ${x.task} / ${x.condition} #${x.run}: migration failed: ${s.migrationError}`);
    else for (const ch of s.checks.filter((c) => !c.ok)) lines.push(`- ${x.task} / ${x.condition} #${x.run}: ${ch.kind === "leak" ? "LEAK" : "broken"}, ${ch.name}: ${ch.detail}`);
  }
  await Deno.writeTextFile(`${dir}/results.md`, lines.join("\n") + "\n");
}
