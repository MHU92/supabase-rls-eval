-- Enable RLS on all tables
alter table public.products enable row level security;
alter table public.cart_items enable row level security;
alter table public.orders enable row level security;

-- Remove Supabase's default table grants, then grant only what the rule needs
revoke all on public.products from anon, authenticated;
revoke all on public.cart_items from anon, authenticated;
revoke all on public.orders from anon, authenticated;

grant select on public.products to anon, authenticated;
grant select, insert, update, delete on public.cart_items to authenticated;
grant select, insert on public.orders to authenticated;

-- products: anyone, including signed-out visitors, can read
drop policy if exists "products_select_public" on public.products;
create policy "products_select_public"
  on public.products
  for select
  to anon, authenticated
  using (true);

-- cart_items: any signed-in user (anonymous or permanent) manages only their own rows
drop policy if exists "cart_items_select_own" on public.cart_items;
create policy "cart_items_select_own"
  on public.cart_items
  for select
  to authenticated
  using (user_id = (select auth.uid()));

drop policy if exists "cart_items_insert_own" on public.cart_items;
create policy "cart_items_insert_own"
  on public.cart_items
  for insert
  to authenticated
  with check (user_id = (select auth.uid()));

drop policy if exists "cart_items_update_own" on public.cart_items;
create policy "cart_items_update_own"
  on public.cart_items
  for update
  to authenticated
  using (user_id = (select auth.uid()))
  with check (user_id = (select auth.uid()));

drop policy if exists "cart_items_delete_own" on public.cart_items;
create policy "cart_items_delete_own"
  on public.cart_items
  for delete
  to authenticated
  using (user_id = (select auth.uid()));

-- orders: only permanent (non-anonymous) users can place orders and read their own
drop policy if exists "orders_select_own_permanent" on public.orders;
create policy "orders_select_own_permanent"
  on public.orders
  for select
  to authenticated
  using (
    user_id = (select auth.uid())
    and coalesce((select auth.jwt() ->> 'is_anonymous')::boolean, false) = false
  );

drop policy if exists "orders_insert_own_permanent" on public.orders;
create policy "orders_insert_own_permanent"
  on public.orders
  for insert
  to authenticated
  with check (
    user_id = (select auth.uid())
    and coalesce((select auth.jwt() ->> 'is_anonymous')::boolean, false) = false
  );
