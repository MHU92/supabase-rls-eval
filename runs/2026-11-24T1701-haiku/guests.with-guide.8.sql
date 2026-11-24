-- Migration: RLS for products, cart_items, orders
-- Access rule:
--   products:   anyone (anon + authenticated, incl. anonymous sign-ins) can read
--   cart_items: any signed-in user (incl. anonymous) manages only their own rows
--   orders:     only permanent (non-anonymous) users insert/read their own rows

-- ---------------------------------------------------------------------------
-- 1. Enable RLS and reset grants
-- ---------------------------------------------------------------------------
alter table public.products   enable row level security;
alter table public.cart_items enable row level security;
alter table public.orders     enable row level security;

revoke all on table public.products   from anon, authenticated;
revoke all on table public.cart_items from anon, authenticated;
revoke all on table public.orders     from anon, authenticated;

grant select on table public.products to anon, authenticated;
grant select, insert, update, delete on table public.cart_items to authenticated;
grant select, insert on table public.orders to authenticated;

-- ---------------------------------------------------------------------------
-- 2. Policies
-- ---------------------------------------------------------------------------

-- products: public read
create policy "Anyone can browse products"
on public.products for select
to anon, authenticated
using ( true );

-- cart_items: signed-in users (anonymous or permanent) manage their own cart
create policy "Users can view their own cart items"
on public.cart_items for select
to authenticated
using ( (select auth.uid()) = user_id );

create policy "Users can add to their own cart"
on public.cart_items for insert
to authenticated
with check ( (select auth.uid()) = user_id );

create policy "Users can update their own cart items"
on public.cart_items for update
to authenticated
using ( (select auth.uid()) = user_id )
with check ( (select auth.uid()) = user_id );

create policy "Users can remove their own cart items"
on public.cart_items for delete
to authenticated
using ( (select auth.uid()) = user_id );

-- orders: permanent (non-anonymous) users only
create policy "Permanent users can place their own orders"
on public.orders for insert
to authenticated
with check (
  (select auth.uid()) = user_id
  and coalesce((select auth.jwt()->>'is_anonymous'), 'false') = 'false'
);

create policy "Permanent users can view their own orders"
on public.orders for select
to authenticated
using (
  (select auth.uid()) = user_id
  and coalesce((select auth.jwt()->>'is_anonymous'), 'false') = 'false'
);

-- ---------------------------------------------------------------------------
-- 3. Indexes for policy filter columns
-- ---------------------------------------------------------------------------
create index if not exists cart_items_user_id_idx on public.cart_items using btree (user_id);
create index if not exists orders_user_id_idx     on public.orders     using btree (user_id);
