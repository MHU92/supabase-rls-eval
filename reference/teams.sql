-- Membership lookups in security definer functions, so policies on team_members do not query themselves.
create function public.is_team_member(t int) returns boolean language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.team_members m where m.team_id = t and m.user_id = (select auth.uid()))
$$;
create function public.is_team_admin(t int) returns boolean language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.team_members m where m.team_id = t and m.user_id = (select auth.uid()) and m.role = 'admin')
$$;
revoke execute on function public.is_team_member(int), public.is_team_admin(int) from anon;

alter table public.teams enable row level security;
alter table public.team_members enable row level security;
alter table public.projects enable row level security;
revoke all on public.teams, public.team_members, public.projects from anon;

create policy "teams: members read" on public.teams for select to authenticated using (public.is_team_member(id));

create policy "members: team reads" on public.team_members for select to authenticated using (public.is_team_member(team_id));
create policy "members: admins add" on public.team_members for insert to authenticated with check (public.is_team_admin(team_id));
create policy "members: admins change" on public.team_members for update to authenticated
  using (public.is_team_admin(team_id)) with check (public.is_team_admin(team_id));
create policy "members: admins remove" on public.team_members for delete to authenticated using (public.is_team_admin(team_id));

create policy "projects: team reads" on public.projects for select to authenticated using (public.is_team_member(team_id));
create policy "projects: admins create" on public.projects for insert to authenticated with check (public.is_team_admin(team_id));
create policy "projects: admins change" on public.projects for update to authenticated
  using (public.is_team_admin(team_id)) with check (public.is_team_admin(team_id));
create policy "projects: admins delete" on public.projects for delete to authenticated using (public.is_team_admin(team_id));
