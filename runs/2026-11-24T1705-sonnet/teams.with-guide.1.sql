-- Helper functions (security definer) avoid recursive policies on team_members.
create schema if not exists private;

create function private.user_team_ids()
returns setof int
language sql
security definer
set search_path = ''
stable
as $$
  select team_id from public.team_members
  where user_id = (select auth.uid())
$$;

create function private.admin_team_ids()
returns setof int
language sql
security definer
set search_path = ''
stable
as $$
  select team_id from public.team_members
  where user_id = (select auth.uid()) and role = 'admin'
$$;

revoke execute on function private.user_team_ids() from public, anon, authenticated;
revoke execute on function private.admin_team_ids() from public, anon, authenticated;
grant usage on schema private to authenticated;
grant execute on function private.user_team_ids() to authenticated;
grant execute on function private.admin_team_ids() to authenticated;

-- Indexes for policy filter columns (team_members PK only covers team_id first).
create index if not exists team_members_user_id_idx on public.team_members using btree (user_id);
create index if not exists projects_team_id_idx on public.projects using btree (team_id);

-- Enable RLS
alter table public.teams enable row level security;
alter table public.team_members enable row level security;
alter table public.projects enable row level security;

-- Grants: revoke defaults, grant back only what is needed
revoke all on table public.teams from anon, authenticated;
revoke all on table public.team_members from anon, authenticated;
revoke all on table public.projects from anon, authenticated;

grant select on table public.teams to authenticated;
grant select, insert, delete on table public.team_members to authenticated;
grant select, insert, update, delete on table public.projects to authenticated;

-- teams
create policy "Members can view their teams"
on public.teams for select
to authenticated
using ( id in (select private.user_team_ids()) );

-- team_members
create policy "Members can view members of their teams"
on public.team_members for select
to authenticated
using ( team_id in (select private.user_team_ids()) );

create policy "Admins can add members to their teams"
on public.team_members for insert
to authenticated
with check ( team_id in (select private.admin_team_ids()) );

create policy "Admins can remove members from their teams"
on public.team_members for delete
to authenticated
using ( team_id in (select private.admin_team_ids()) );

-- projects
create policy "Members can view their team projects"
on public.projects for select
to authenticated
using ( team_id in (select private.user_team_ids()) );

create policy "Admins can create team projects"
on public.projects for insert
to authenticated
with check ( team_id in (select private.admin_team_ids()) );

create policy "Admins can update team projects"
on public.projects for update
to authenticated
using ( team_id in (select private.admin_team_ids()) )
with check ( team_id in (select private.admin_team_ids()) );

create policy "Admins can delete team projects"
on public.projects for delete
to authenticated
using ( team_id in (select private.admin_team_ids()) );
