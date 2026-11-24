-- Access rule migration: public products, per-user carts, permanent-user orders.

-- 1. Enable RLS on all three tables.
alter table public.products enable row level security;
alter table public.cart_items enable row level security;
alter table public.orders enable row level security;

-- 2. Remove Supabase's default broad grants so only the intended operations remain.
revoke all on public.products from anon, authenticated;
revoke all on public.cart_items from anon, authenticated;
revoke all on public.orders from anon, authenticated;

grant select on public.products to anon, authenticated;
grant select, insert, update, delete on public.cart_items to authenticated;
grant select, insert on public.orders to authenticated;

-- 3. products: anyone (including signed-out visitors) can read. No write policies, so writes are denied.
drop policy if exists products_select_public on public.products;
create policy products_select_public
  on public.products
  for select
  to anon, authenticated
  using (true);

-- 4. cart_items: any signed-in user (including anonymous) manages only their own rows.
drop policy if exists cart_items_own_all on public.cart_items;
create policy cart_items_own_all
  on public.cart_items
  for all
  to authenticated
  using (user_id = (select auth.uid()))
  with check (user_id = (select auth.uid()));

-- 5. orders: only permanent (non-anonymous) users can place and read their own orders.
--    A missing is_anonymous claim is treated as anonymous, so the default is deny.
drop policy if exists orders_permanent_select_own on public.orders;
create policy orders_permanent_select_own
  on public.orders
  for select
  to authenticated
  using (
    user_id = (select auth.uid())
    and coalesce((select (auth.jwt() ->> 'is_anonymous')::boolean), true) = false
  );

drop policy if exists orders_permanent_insert_own on public.orders;
create policy orders_permanent_insert_own
  on public.orders
  for insert
  to authenticated
  with check (
    user_id = (select auth.uid())
    and coalesce((select (auth.jwt() ->> 'is_anonymous')::boolean), true) = false
  );
