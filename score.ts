// Scores a migration against one task: fresh database, Supabase auth shim, task schema, then the migration
// as the non-superuser `migrator`, then every check in its own rolled-back transaction as the check's user.
// Usage: deno run --allow-run=psql --allow-read --allow-env score.ts <task-id> <migration.sql>
// Needs PGHOST, PGPORT and PGUSER (a superuser of a throwaway cluster).

import { type Check, type Task, TASKS } from "./tasks.ts";

export type CheckResult = { name: string; ok: boolean; kind: "leak" | "broken" | null; detail: string };
export type Score = { task: string; migrationError: string | null; checks: CheckResult[]; leaks: number; broken: number; passed: number; total: number };

const SHIM = await Deno.readTextFile(new URL("./shim.sql", import.meta.url));

async function psql(db: string, sql: string, quiet = true): Promise<{ ok: boolean; out: string; err: string }> {
  const args = ["-X", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-d", db];
  if (quiet) args.push("-q");
  const cmd = new Deno.Command("psql", {
    args,
    stdin: "piped",
    stdout: "piped",
    stderr: "piped",
    env: { PGOPTIONS: "-c statement_timeout=5000 -c client_min_messages=warning" },
  });
  const child = cmd.spawn();
  const w = child.stdin.getWriter();
  await w.write(new TextEncoder().encode(sql));
  await w.close();
  const { code, stdout, stderr } = await child.output();
  return { ok: code === 0, out: new TextDecoder().decode(stdout).trim(), err: new TextDecoder().decode(stderr).trim() };
}

const lit = (s: string) => "'" + s.replaceAll("'", "''") + "'";

function wrap(task: Task, check: Check, body: string) {
  const u = task.users[check.as];
  if (!u) throw new Error(`unknown user ${check.as} in ${task.id}`);
  const claims = u.claims ? `set local "request.jwt.claims" = ${lit(JSON.stringify(u.claims))};\n` : "";
  return `begin;\nset local role ${u.role};\n${claims}${body};\nrollback;\n`;
}

async function runCheck(db: string, task: Task, check: Check): Promise<CheckResult> {
  if ("read" in check) {
    const r = await psql(db, wrap(task, check, `select coalesce(json_agg(x.id::text order by x.id::text), '[]') from (${check.read}) x`));
    const seen: string[] = r.ok ? JSON.parse(r.out || "[]") : [];
    const extra = seen.filter((id) => !check.expect.includes(id));
    const missing = check.expect.filter((id) => !seen.includes(id));
    const err = r.ok ? "" : ` (error: ${firstLine(r.err)})`;
    if (extra.length) return { name: check.name, ok: false, kind: "leak", detail: `sees ${extra.join(", ")} it must not see${err}` };
    if (missing.length) return { name: check.name, ok: false, kind: "broken", detail: `misses ${missing.join(", ")}${err}` };
    return { name: check.name, ok: true, kind: null, detail: "" };
  }
  const r = await psql(db, wrap(task, check, check.write), false);
  const tag = r.out.split("\n").map((l) => l.trim()).reverse().find((l) => /^(INSERT \d+|UPDATE|DELETE) \d+$/.test(l));
  const affected = r.ok && tag ? Number(tag.split(" ").at(-1)) : 0;
  const went = r.ok && affected > 0;
  const how = r.ok ? `${affected} row(s)` : `error: ${firstLine(r.err)}`;
  if (check.expect === "deny" && went) return { name: check.name, ok: false, kind: "leak", detail: `went through, ${how}` };
  if (check.expect === "allow" && !went) return { name: check.name, ok: false, kind: "broken", detail: `blocked, ${how}` };
  return { name: check.name, ok: true, kind: null, detail: "" };
}

const firstLine = (s: string) => (s.split("\n").find((l) => l.includes("ERROR")) ?? s.split("\n")[0] ?? "").replace(/^.*ERROR:\s*/, "").slice(0, 140);

export async function score(taskId: string, migration: string): Promise<Score> {
  const task = TASKS.find((t) => t.id === taskId);
  if (!task) throw new Error(`unknown task ${taskId}`);
  const db = `rls_${task.id}_${crypto.randomUUID().slice(0, 8)}`;
  const admin = Deno.env.get("PGDATABASE_ADMIN") ?? "postgres";
  const created = await psql(admin, `create database ${db};`);
  if (!created.ok) throw new Error(created.err);
  try {
    // Like Supabase's postgres role, the migrator may create schemas (e.g. a private schema for helper functions).
    const prep = await psql(db, `${SHIM}\ngrant create on database ${db} to migrator;\ngrant insert on auth.users to migrator;\nset role migrator;\n${task.setup}\nreset role;\nrevoke insert on auth.users from migrator;\n`);
    if (!prep.ok) throw new Error(`setup of ${task.id} failed: ${prep.err}`);
    const mig = await psql(db, `set role migrator;\n${migration}\n`);
    const migrationError = mig.ok ? null : firstLine(mig.err);
    const checks: CheckResult[] = [];
    for (const c of task.checks) {
      checks.push(migrationError ? { name: c.name, ok: false, kind: "broken", detail: "migration failed" } : await runCheck(db, task, c));
    }
    const leaks = checks.filter((c) => c.kind === "leak").length;
    const broken = checks.filter((c) => c.kind === "broken").length;
    return { task: task.id, migrationError, checks, leaks, broken, passed: checks.filter((c) => c.ok).length, total: checks.length };
  } finally {
    await psql(admin, `drop database if exists ${db} with (force);`);
  }
}

if (import.meta.main) {
  const [taskId, file] = Deno.args;
  if (!taskId || !file) {
    console.error("usage: score.ts <task-id> <migration.sql>");
    Deno.exit(2);
  }
  const s = await score(taskId, await Deno.readTextFile(file));
  if (s.migrationError) console.log(`migration failed: ${s.migrationError}`);
  for (const c of s.checks) console.log(`${c.ok ? "pass" : c.kind === "leak" ? "LEAK" : "FAIL"}  ${c.name}${c.detail ? `  (${c.detail})` : ""}`);
  console.log(`${s.task}: ${s.passed}/${s.total} passed, ${s.leaks} leak(s), ${s.broken} broken`);
}
