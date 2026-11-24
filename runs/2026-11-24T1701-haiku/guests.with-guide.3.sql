-- Migration: RLS for products, cart_items, orders
-- Rule: products readable by everyone; cart_items owned by any signed-in user
-- (incl. anonymous); orders only for permanent (non-anonymous) users.

-- 1. Enable RLS
alter table public.products enable row level security;
alter table public.cart_items enable row level security;
alter table public.orders enable row level security;

-- 2. Revoke default grants, then grant back only what each role needs
revoke all on table public.products from anon, authenticated;
revoke all on table public.cart_items from anon, authenticated;
revoke all on table public.orders from anon, authenticated;

grant select on table public.products to anon, authenticated;
grant select, insert, update, delete on table public.cart_items to authenticated;
grant select, insert on table public.orders to authenticated;

-- 3. Indexes for policy filter columns
create index if not exists cart_items_user_id_idx on public.cart_items using btree (user_id);
create index if not exists orders_user_id_idx on public.orders using btree (user_id);

-- 4. Policies

-- products: public read
create policy "Anyone can read products"
on public.products for select
to anon, authenticated
using ( true );

-- cart_items: owner-only, signed-in incl. anonymous
create policy "Users can read their own cart items"
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
create policy "Permanent users can read their own orders"
on public.orders for select
to authenticated
using (
  (select auth.uid()) = user_id
  and coalesce((select auth.jwt()->>'is_anonymous'), 'false') = 'false'
);

create policy "Permanent users can place their own orders"
on public.orders for insert
to authenticated
with check (
  (select auth.uid()) = user_id
  and coalesce((select auth.jwt()->>'is_anonymous'), 'false') = 'false'
);
