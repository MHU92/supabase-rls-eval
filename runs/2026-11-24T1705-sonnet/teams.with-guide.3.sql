-- Helper functions live in a non-exposed schema and run as owner (bypass RLS),
-- which avoids infinite recursion in the team_members policies.
create schema if not exists private;

create or replace function private.user_team_ids()
returns setof int
language sql
security definer
set search_path = ''
stable
as $$
  select team_id from public.team_members
  where user_id = (select auth.uid())
$$;

create or replace function private.admin_team_ids()
returns setof int
language sql
security definer
set search_path = ''
stable
as $$
  select team_id from public.team_members
  where user_id = (select auth.uid()) and role = 'admin'
$$;

revoke execute on function private.user_team_ids() from public, anon;
revoke execute on function private.admin_team_ids() from public, anon;
grant usage on schema private to authenticated;
grant execute on function private.user_team_ids() to authenticated;
grant execute on function private.admin_team_ids() to authenticated;

-- Indexes for policy filter columns (user_id is not the leading PK column).
create index if not exists team_members_user_id_idx on public.team_members using btree (user_id);
create index if not exists projects_team_id_idx on public.projects using btree (team_id);

-- Enable RLS and reset grants.
alter table public.teams enable row level security;
alter table public.team_members enable row level security;
alter table public.projects enable row level security;

revoke all on table public.teams from anon, authenticated;
revoke all on table public.team_members from anon, authenticated;
revoke all on table public.projects from anon, authenticated;

grant select on table public.teams to authenticated;
grant select, insert, delete on table public.team_members to authenticated;
grant select, insert, delete on table public.projects to authenticated;
grant update (name) on table public.projects to authenticated;

-- teams: members can see their own teams.
create policy "Members can view their teams"
on public.teams for select
to authenticated
using ( id in (select private.user_team_ids()) );

-- team_members: members see co-members; admins add/remove.
create policy "Members can view their team's members"
on public.team_members for select
to authenticated
using ( team_id in (select private.user_team_ids()) );

create policy "Admins can add members to their team"
on public.team_members for insert
to authenticated
with check ( team_id in (select private.admin_team_ids()) );

create policy "Admins can remove members from their team"
on public.team_members for delete
to authenticated
using ( team_id in (select private.admin_team_ids()) );

-- projects: members read; admins create, rename, delete.
create policy "Members can view their team's projects"
on public.projects for select
to authenticated
using ( team_id in (select private.user_team_ids()) );

create policy "Admins can create projects for their team"
on public.projects for insert
to authenticated
with check ( team_id in (select private.admin_team_ids()) );

create policy "Admins can update their team's projects"
on public.projects for update
to authenticated
using ( team_id in (select private.admin_team_ids()) )
with check ( team_id in (select private.admin_team_ids()) );

create policy "Admins can delete their team's projects"
on public.projects for delete
to authenticated
using ( team_id in (select private.admin_team_ids()) );
