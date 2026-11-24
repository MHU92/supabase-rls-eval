-- Access rules:
--   products:   readable by everyone, including signed-out visitors (role anon)
--   cart_items: any signed-in user (including anonymous) manages only their own rows
--   orders:     only permanent (non-anonymous) users can insert and read their own rows

-- Anonymous sign-ins issue JWTs with an is_anonymous claim.
-- Treat a missing claim as "not anonymous", and a signed-out request as "not permanent".

-- 1. products: public read-only
alter table public.products enable row level security;

revoke all on public.products from anon, authenticated;
grant select on public.products to anon, authenticated;

create policy "products_select_public"
  on public.products
  for select
  to anon, authenticated
  using (true);

-- 2. cart_items: owner-only, signed-in users (anonymous included)
alter table public.cart_items enable row level security;

revoke all on public.cart_items from anon, authenticated;
grant select, insert, update, delete on public.cart_items to authenticated;

create policy "cart_items_select_own"
  on public.cart_items
  for select
  to authenticated
  using (user_id = (select auth.uid()));

create policy "cart_items_insert_own"
  on public.cart_items
  for insert
  to authenticated
  with check (user_id = (select auth.uid()));

create policy "cart_items_update_own"
  on public.cart_items
  for update
  to authenticated
  using (user_id = (select auth.uid()))
  with check (user_id = (select auth.uid()));

create policy "cart_items_delete_own"
  on public.cart_items
  for delete
  to authenticated
  using (user_id = (select auth.uid()));

-- 3. orders: permanent users only, read and insert own rows
alter table public.orders enable row level security;

revoke all on public.orders from anon, authenticated;
grant select, insert on public.orders to authenticated;

create policy "orders_select_own_permanent"
  on public.orders
  for select
  to authenticated
  using (
    user_id = (select auth.uid())
    and coalesce((select auth.jwt() ->> 'is_anonymous')::boolean, false) = false
  );

create policy "orders_insert_own_permanent"
  on public.orders
  for insert
  to authenticated
  with check (
    user_id = (select auth.uid())
    and coalesce((select auth.jwt() ->> 'is_anonymous')::boolean, false) = false
  );
