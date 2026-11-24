// Asks a model for each task's migration, with and without the Supabase RLS guide in context, and scores every answer.
// Usage: deno run --allow-run=psql,claude --allow-read --allow-write=runs --allow-env --allow-net=supabase.com run.ts [model] [runs]
// The model is called through `claude -p` with every tool switched off, so it can only answer with text.

import { score } from "./score.ts";
import { TASKS } from "./tasks.ts";
import { type Row, writeReport } from "./report.ts";

const model = Deno.args[0] ?? "haiku";
const runs = Number(Deno.args[1] ?? 3);
const GUIDE_URL = "https://supabase.com/docs/guides/database/postgres/row-level-security.md";

// The page opens with a note addressed to AI agents; drop it so the guide is reference text only.
const guide = (await (await fetch(GUIDE_URL)).text()).split("\n").filter((l) => !l.startsWith("> Note for AI agents")).join("\n");

const schemaOf = (setup: string) =>
  setup.split(";").map((s) => s.trim()).filter((s) => s.startsWith("create")).map((s) => s.replace(/\n\s+/g, "\n  ") + ";").join("\n");

function prompt(taskPrompt: string, setup: string, withGuide: boolean) {
  return [
    "You are working on a Supabase project. Write one SQL migration that implements the access rule below with Row Level Security.",
    "The tables already exist with data and still have Supabase's default grants. Reply with exactly one ```sql code block and nothing else.",
    "",
    "Existing schema:",
    "```sql",
    schemaOf(setup),
    "```",
    "",
    `Access rule: ${taskPrompt}`,
    ...(withGuide ? ["", "Reference, the Supabase documentation on Row Level Security:", "", guide] : []),
  ].join("\n");
}

async function ask(text: string): Promise<{ sql: string; costUsd: number }> {
  // An empty working directory, so the model has no files around it.
  const cwd = `${dir}/.empty-${crypto.randomUUID().slice(0, 8)}`;
  await Deno.mkdir(cwd);
  const cmd = new Deno.Command("claude", {
    // Project settings only (the directory is empty), so personal settings such as a reply language do not leak in.
    args: ["-p", "--model", model, "--tools", "", "--strict-mcp-config", "--setting-sources", "project", "--no-session-persistence", "--output-format", "json"],
    cwd,
    stdin: "piped",
    stdout: "piped",
    stderr: "piped",
  });
  const child = cmd.spawn();
  const w = child.stdin.getWriter();
  await w.write(new TextEncoder().encode(text));
  await w.close();
  const { stdout } = await child.output();
  await Deno.remove(cwd, { recursive: true });
  const out = JSON.parse(new TextDecoder().decode(stdout));
  const answer: string = out.result ?? "";
  const m = answer.match(/```sql\s*\n([\s\S]*?)```/);
  return { sql: m ? m[1] : answer, costUsd: out.total_cost_usd ?? 0 };
}

const stamp = new Date().toISOString().slice(0, 16).replace(":", "");
const dir = `runs/${stamp}-${model}`;
await Deno.mkdir(dir, { recursive: true });

const jobs: (() => Promise<Row>)[] = [];
for (const t of TASKS) {
  for (const condition of ["baseline", "with-guide"]) {
    for (let run = 1; run <= runs; run++) {
      jobs.push(async () => {
        const { sql, costUsd } = await ask(prompt(t.prompt, t.setup, condition === "with-guide"));
        await Deno.writeTextFile(`${dir}/${t.id}.${condition}.${run}.sql`, sql);
        const s = await score(t.id, sql);
        console.log(`${t.id} ${condition} #${run}: ${s.passed}/${s.total}, ${s.leaks} leak(s), ${s.broken} broken${s.migrationError ? " (migration failed)" : ""}`);
        return { task: t.id, condition, run, score: s, costUsd };
      });
    }
  }
}

const rows: Row[] = [];
const parallel = 6;
for (let i = 0; i < jobs.length; i += parallel) rows.push(...await Promise.all(jobs.slice(i, i + parallel).map((j) => j())));

await writeReport(dir, rows, model, runs);
console.log(`\n${dir}/results.md`);
