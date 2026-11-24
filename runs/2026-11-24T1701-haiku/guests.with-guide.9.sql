-- Migration: RLS for products, cart_items, orders
-- Access rule:
--   products: readable by anyone (anon + authenticated, incl. anonymous sign-ins)
--   cart_items: any signed-in user (incl. anonymous) manages only their own rows
--   orders: only permanent (non-anonymous) users may insert and read their own rows

begin;

-- ---------------------------------------------------------------
-- Helper: true when the JWT belongs to a permanent (non-anonymous) user
-- ---------------------------------------------------------------
create schema if not exists private;

create or replace function private.is_permanent_user()
returns boolean
language sql
stable
security invoker
set search_path = ''
as $$
  select coalesce((select auth.jwt() ->> 'is_anonymous') = 'false', false)
$$;

revoke execute on function private.is_permanent_user() from public;
grant usage on schema private to authenticated;
grant execute on function private.is_permanent_user() to authenticated;

-- ---------------------------------------------------------------
-- products: public read-only catalogue
-- ---------------------------------------------------------------
alter table public.products enable row level security;

revoke all on table public.products from anon, authenticated;
grant select on table public.products to anon, authenticated;

create policy "products_select_public"
on public.products for select
to anon, authenticated
using ( true );

-- ---------------------------------------------------------------
-- cart_items: each signed-in user (anonymous or permanent) owns their rows
-- ---------------------------------------------------------------
alter table public.cart_items enable row level security;

revoke all on table public.cart_items from anon, authenticated;
grant select, insert, update, delete on table public.cart_items to authenticated;

create index if not exists cart_items_user_id_idx
on public.cart_items using btree (user_id);

create policy "cart_items_select_own"
on public.cart_items for select
to authenticated
using ( (select auth.uid()) = user_id );

create policy "cart_items_insert_own"
on public.cart_items for insert
to authenticated
with check ( (select auth.uid()) = user_id );

create policy "cart_items_update_own"
on public.cart_items for update
to authenticated
using ( (select auth.uid()) = user_id )
with check ( (select auth.uid()) = user_id );

create policy "cart_items_delete_own"
on public.cart_items for delete
to authenticated
using ( (select auth.uid()) = user_id );

-- ---------------------------------------------------------------
-- orders: permanent users only; read and place their own orders
-- ---------------------------------------------------------------
alter table public.orders enable row level security;

revoke all on table public.orders from anon, authenticated;
grant select, insert on table public.orders to authenticated;

create index if not exists orders_user_id_idx
on public.orders using btree (user_id);

create policy "orders_select_own_permanent"
on public.orders for select
to authenticated
using (
  (select auth.uid()) = user_id
  and (select private.is_permanent_user())
);

create policy "orders_insert_own_permanent"
on public.orders for insert
to authenticated
with check (
  (select auth.uid()) = user_id
  and (select private.is_permanent_user())
);

commit;
