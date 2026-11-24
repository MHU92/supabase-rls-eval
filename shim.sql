-- Minimal Supabase auth environment on plain Postgres, so every task runs in a fresh, local database.
-- Mirrors what matters for RLS: the roles anon, authenticated and service_role, auth.uid(), auth.jwt(),
-- auth.users, and the default grants of an existing Supabase project (every privilege for every API role).

do $$ begin
  if not exists (select from pg_roles where rolname = 'anon') then create role anon nologin noinherit; end if;
  if not exists (select from pg_roles where rolname = 'authenticated') then create role authenticated nologin noinherit; end if;
  if not exists (select from pg_roles where rolname = 'service_role') then create role service_role nologin noinherit bypassrls; end if;
end $$;

create schema auth;
grant usage on schema auth to anon, authenticated, service_role;

create table auth.users (
  id uuid primary key,
  email text,
  is_anonymous boolean not null default false,
  raw_app_meta_data jsonb not null default '{}',
  raw_user_meta_data jsonb not null default '{}'
);

create function auth.jwt() returns jsonb language sql stable as $$
  select coalesce(nullif(current_setting('request.jwt.claims', true), ''), '{}')::jsonb
$$;

create function auth.uid() returns uuid language sql stable as $$
  select nullif(auth.jwt() ->> 'sub', '')::uuid
$$;

create function auth.role() returns text language sql stable as $$
  select auth.jwt() ->> 'role'
$$;

-- Migrations run as `migrator`, a non-superuser that owns the tables, like the `postgres` role on Supabase.
-- That also keeps agent-written SQL away from superuser features such as COPY ... PROGRAM.
do $$ begin
  if not exists (select from pg_roles where rolname = 'migrator') then create role migrator nologin; end if;
end $$;
grant usage on schema auth to migrator;
grant select, references on auth.users to migrator;
grant usage on schema public to anon, authenticated, service_role;
grant usage, create on schema public to migrator;
alter default privileges for role migrator in schema public grant all on tables to anon, authenticated, service_role;
alter default privileges for role migrator in schema public grant all on sequences to anon, authenticated, service_role;
alter default privileges for role migrator in schema public grant all on functions to anon, authenticated, service_role;
