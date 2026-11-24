-- Typical mistake: policies on team_members that query team_members, which Postgres rejects as infinite recursion.
alter table public.team_members enable row level security;
alter table public.projects enable row level security;
create policy "members: team reads" on public.team_members for select
  using (team_id in (select team_id from public.team_members where user_id = auth.uid()));
create policy "members: admins manage" on public.team_members for all
  using (team_id in (select team_id from public.team_members where user_id = auth.uid() and role = 'admin'));
create policy "projects: team reads" on public.projects for select
  using (team_id in (select team_id from public.team_members where user_id = auth.uid()));
create policy "projects: admins write" on public.projects for all
  using (team_id in (select team_id from public.team_members where user_id = auth.uid() and role = 'admin'));
