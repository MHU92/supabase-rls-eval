-- Migration: RLS for products, cart_items, orders
-- Rule: products readable by everyone; cart_items owned by any signed-in user
-- (including anonymous); orders only for permanent (non-anonymous) users.

-- products: public read
alter table public.products enable row level security;
revoke all on table public.products from anon, authenticated;
grant select on table public.products to anon, authenticated;

create policy "Anyone can browse products"
on public.products for select
to anon, authenticated
using ( true );

-- cart_items: each signed-in user (anonymous or permanent) manages own rows
alter table public.cart_items enable row level security;
revoke all on table public.cart_items from anon, authenticated;
grant select, insert, update, delete on table public.cart_items to authenticated;

create policy "Users read own cart items"
on public.cart_items for select
to authenticated
using ( (select auth.uid()) = user_id );

create policy "Users add own cart items"
on public.cart_items for insert
to authenticated
with check ( (select auth.uid()) = user_id );

create policy "Users update own cart items"
on public.cart_items for update
to authenticated
using ( (select auth.uid()) = user_id )
with check ( (select auth.uid()) = user_id );

create policy "Users delete own cart items"
on public.cart_items for delete
to authenticated
using ( (select auth.uid()) = user_id );

create index if not exists cart_items_user_id_idx
on public.cart_items using btree (user_id);

-- orders: permanent (non-anonymous) users only, own rows
alter table public.orders enable row level security;
revoke all on table public.orders from anon, authenticated;
grant select, insert on table public.orders to authenticated;

create policy "Permanent users read own orders"
on public.orders for select
to authenticated
using (
  (select auth.uid()) = user_id
  and coalesce((select auth.jwt()->>'is_anonymous'), 'false') = 'false'
);

create policy "Permanent users place orders"
on public.orders for insert
to authenticated
with check (
  (select auth.uid()) = user_id
  and coalesce((select auth.jwt()->>'is_anonymous'), 'false') = 'false'
);

create index if not exists orders_user_id_idx
on public.orders using btree (user_id);
