# rls-eval: do coding agents write Row Level Security that holds?

A small eval for one question: when you ask a coding agent for Supabase RLS policies, are the policies safe, and does giving the agent Supabase's own guidance make them safer?

It does not read the SQL. It applies the agent's migration to a fresh Postgres with a Supabase-style auth setup and then **queries the database as different users**: Alice, Bob, a signed-out visitor, a user who edited their own `user_metadata`, an anonymous sign-in. A policy that looks right but lets Bob read Alice's notes fails here, however tidy it reads.

## How it works

- **6 tasks, 66 checks** (`tasks.ts`). Each task is an existing schema with seed data plus a plain-language access rule, the way a developer would ask an agent: private notes, team projects with admins, support tickets with an admin flag, a blog with drafts, documents shared between users, a shop with anonymous sign-ins.
- **Scorer** (`score.ts`). Fresh database per answer, a minimal Supabase auth shim (`shim.sql`: `anon`, `authenticated`, `auth.uid()`, `auth.jwt()`, Supabase's default grants), the task schema, then the migration as a non-superuser that owns the tables. Every check runs in its own rolled-back transaction as its user. Two kinds of failure are counted separately:
  - **leak**: a user sees or changes something they must not (the expensive kind)
  - **broken**: a legitimate read or write is blocked, or the migration does not run
- **Runner** (`run.ts`). Calls a model through `claude -p` with all tools switched off, in two conditions: `baseline` (task only) and `with-guide` (task plus the [Supabase RLS guide](https://supabase.com/docs/guides/database/postgres/row-level-security) in context, a stand-in for docs or agent skills). Several runs per task and condition, because one run says little.

## Does the scorer catch real mistakes?

The reference solutions (`reference/`) pass 66/66. Four typical mistakes (`naive/`) are caught:

| Mistake | Result |
|---|---|
| Admin flag read from `user_metadata`, which users can edit themselves | 2 leaks: a user who set `role: admin` on herself reads and edits other tickets |
| One `for all` policy without `to` or `with check` on a blog | 6 leaks: visitors write posts, users edit and delete others' posts |
| Policies on `team_members` that query `team_members` | 6 broken: infinite recursion, nobody can read their team |
| `documents` and `document_shares` policies that query each other | 5 broken: infinite recursion |

It also caught a mistake of mine: my first reference for shared documents let an editor make themselves the owner, because the update check tested `auth.uid() = owner_id` on the new row.

## Results (24 November 2026)

180 runs: Haiku with 10 runs and Sonnet with 5 runs per task and condition. Full tables and every answer are in `runs/`.

| | Haiku, baseline | Haiku, with guide | Sonnet, baseline | Sonnet, with guide |
|---|---|---|---|---|
| Runs without a leak | 60/60 | 58/60 | 30/30 | 30/30 |
| Runs fully correct | 59/60 | 51/60 | 30/30 | 30/30 |
| Cost (list price) | $0.10 | $0.22 | $0.64 | $2.07 |

What I take from it:

- **Sonnet solved all six tasks in both conditions.** For these tasks the guide triples the cost without a measurable gain. Harder tasks are needed to see a difference at that level.
- **Haiku got worse with the guide**, almost entirely on one task, shared documents: 3 of 10 runs fully correct with the guide, 9 of 10 without.
  - 2 runs leaked: an editor can make themselves the owner. Both use the same expression in `using` and `with check` for editors. That is the pattern the guide shows for an order shared by buyer and seller, and it is right there. Here it keeps the editor on the row but does not stop them from changing the owner column. My own first reference had the same bug.
  - 5 runs hit infinite recursion between the policies of `documents` and `document_shares`.
  - Elsewhere, 2 migrations failed: a `private` schema used without creating it, and a stray code fence.
- **More context is not automatically safer.** A short, task-shaped rule, such as "when someone other than the owner may update a row, pin the owner column in `with check`", is a candidate for an agent skill. This eval is how you would find out whether it helps.

## Limits

- Plain Postgres 14 with a shim, not the Supabase stack. No PostgREST, Storage, Realtime or views with `security_invoker` (Postgres 15+). Running the same checks against `supabase start` is the obvious next step.
- "Guide in context" is a stand-in. It is not the Supabase MCP server or the agent skills, which an agent would use through tool calls.
- Small numbers: 6 tasks, 10 runs per condition for Haiku and 5 for Sonnet. Enough to see a pattern, not to rank models.
- I wrote the tasks and checks myself. Each check is one sentence in `tasks.ts`, so they are easy to review or extend.

## What I would build next

1. The same tasks with the Supabase MCP server and agent skills as the treatment, so the number answers "does our tooling make agents safer".
2. Export the checks as pgTAP tests, so a developer can run them with `supabase test db`.
3. More tasks where agents are known to slip: views over protected tables, Storage policies, Realtime, `security definer` functions in exposed schemas.
4. A CI gate: a change to a skill or tool description may not raise the leak rate.

## Run it

Needs Deno, `psql` and a throwaway Postgres you can use as superuser.

```sh
export PGHOST=127.0.0.1 PGPORT=54329 PGUSER=postgres
deno run --allow-run=psql --allow-read --allow-env score.ts notes reference/notes.sql
deno run --allow-run=psql,claude --allow-read --allow-write=runs --allow-env --allow-net=supabase.com run.ts haiku 10
deno run --allow-run=psql --allow-read --allow-write=runs --allow-env rescore.ts runs/<dir>
```

Answers and scores of every run are in `runs/`.
