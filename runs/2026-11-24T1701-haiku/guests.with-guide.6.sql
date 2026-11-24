-- Migration: enforce shop access rules with RLS
-- Products: public read (anon + authenticated, including anonymous sign-ins)
-- Cart items: any signed-in user (incl. anonymous) manages own rows
-- Orders: only permanent (non-anonymous) users insert/read their own rows

-- ---------------------------------------------------------------
-- Helper: true when the JWT is an anonymous sign-in
-- ---------------------------------------------------------------
create or replace function public.is_anonymous_user()
returns boolean
language sql
stable
security invoker
set search_path = ''
as $$
  select coalesce((select auth.jwt() ->> 'is_anonymous')::boolean, false)
$$;

-- ---------------------------------------------------------------
-- products
-- ---------------------------------------------------------------
alter table public.products enable row level security;

revoke all on table public.products from anon, authenticated;
grant select on table public.products to anon, authenticated;

create policy "Anyone can browse products"
on public.products for select
to anon, authenticated
using ( true );

-- ---------------------------------------------------------------
-- cart_items
-- ---------------------------------------------------------------
alter table public.cart_items enable row level security;

revoke all on table public.cart_items from anon, authenticated;
grant select, insert, update, delete on table public.cart_items to authenticated;

create index if not exists cart_items_user_id_idx
on public.cart_items using btree (user_id);

create policy "Users read own cart"
on public.cart_items for select
to authenticated
using ( (select auth.uid()) = user_id );

create policy "Users add to own cart"
on public.cart_items for insert
to authenticated
with check ( (select auth.uid()) = user_id );

create policy "Users update own cart"
on public.cart_items for update
to authenticated
using ( (select auth.uid()) = user_id )
with check ( (select auth.uid()) = user_id );

create policy "Users remove from own cart"
on public.cart_items for delete
to authenticated
using ( (select auth.uid()) = user_id );

-- ---------------------------------------------------------------
-- orders
-- ---------------------------------------------------------------
alter table public.orders enable row level security;

revoke all on table public.orders from anon, authenticated;
grant select, insert on table public.orders to authenticated;

create index if not exists orders_user_id_idx
on public.orders using btree (user_id);

create policy "Permanent users read own orders"
on public.orders for select
to authenticated
using (
  (select auth.uid()) = user_id
  and not (select public.is_anonymous_user())
);

create policy "Permanent users place orders"
on public.orders for insert
to authenticated
with check (
  (select auth.uid()) = user_id
  and not (select public.is_anonymous_user())
);
