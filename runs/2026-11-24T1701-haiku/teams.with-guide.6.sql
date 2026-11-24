-- Migration: team-based RLS for teams, team_members, projects
-- Access rule:
--   * Members can read their own team's projects and see who is in their team.
--   * Only team admins can create, rename, or delete their team's projects,
--     and add or remove members of their team.
--   * No cross-team visibility or change.

-- 1. Helper functions (security definer, search_path pinned, schema-qualified).
create schema if not exists private;

-- Teams the calling user belongs to (any role).
create or replace function private.user_team_ids()
returns setof int
language sql
security definer
set search_path = ''
stable
as $$
  select tm.team_id
  from public.team_members tm
  where tm.user_id = (select auth.uid())
$$;

-- Teams where the calling user is an admin.
create or replace function private.user_admin_team_ids()
returns setof int
language sql
security definer
set search_path = ''
stable
as $$
  select tm.team_id
  from public.team_members tm
  where tm.user_id = (select auth.uid())
    and tm.role = 'admin'
$$;

revoke execute on function private.user_team_ids() from public;
revoke execute on function private.user_admin_team_ids() from public;
grant usage on schema private to authenticated;
grant execute on function private.user_team_ids() to authenticated;
grant execute on function private.user_admin_team_ids() to authenticated;

-- 2. Indexes for policy filter columns.
-- team_members primary key covers team_id; user_id needs its own index.
create index if not exists team_members_user_id_idx
  on public.team_members using btree (user_id);
create index if not exists projects_team_id_idx
  on public.projects using btree (team_id);

-- 3. Enable RLS and reset grants.
alter table public.teams        enable row level security;
alter table public.team_members enable row level security;
alter table public.projects     enable row level security;

revoke all on table public.teams        from anon, authenticated;
revoke all on table public.team_members from anon, authenticated;
revoke all on table public.projects     from anon, authenticated;

-- Members read; writes are gated by policy below.
grant select on table public.teams        to authenticated;
grant select on table public.team_members to authenticated;
grant select, insert, update, delete on table public.projects    to authenticated;
grant insert, delete on table public.team_members to authenticated;

-- 4. teams: members see their own teams. No client writes.
create policy "Members read their teams"
on public.teams for select
to authenticated
using ( id in (select private.user_team_ids()) );

-- 5. team_members: members see who is in their team. Only admins add/remove.
create policy "Members read their team's roster"
on public.team_members for select
to authenticated
using ( team_id in (select private.user_team_ids()) );

create policy "Admins add members to their team"
on public.team_members for insert
to authenticated
with check ( team_id in (select private.user_admin_team_ids()) );

create policy "Admins remove members from their team"
on public.team_members for delete
to authenticated
using ( team_id in (select private.user_admin_team_ids()) );

-- 6. projects: members read; only admins create, rename, delete.
create policy "Members read their team's projects"
on public.projects for select
to authenticated
using ( team_id in (select private.user_team_ids()) );

create policy "Admins create projects for their team"
on public.projects for insert
to authenticated
with check ( team_id in (select private.user_admin_team_ids()) );

create policy "Admins rename their team's projects"
on public.projects for update
to authenticated
using ( team_id in (select private.user_admin_team_ids()) )
with check ( team_id in (select private.user_admin_team_ids()) );

create policy "Admins delete their team's projects"
on public.projects for delete
to authenticated
using ( team_id in (select private.user_admin_team_ids()) );
