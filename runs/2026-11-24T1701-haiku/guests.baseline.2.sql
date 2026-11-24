-- Enable RLS on all shop tables
alter table public.products enable row level security;
alter table public.cart_items enable row level security;
alter table public.orders enable row level security;

-- Remove Supabase's default broad grants for client roles (anon, authenticated).
-- RLS policies below are the only access path for these roles.
revoke all on public.products from anon, authenticated;
revoke all on public.cart_items from anon, authenticated;
revoke all on public.orders from anon, authenticated;

-- products: anyone (signed-out or signed-in) can read; nobody client-side can write
grant select on public.products to anon, authenticated;

create policy products_select_public
  on public.products
  for select
  to anon, authenticated
  using (true);

-- cart_items: signed-in users (including anonymous) manage only their own rows
grant select, insert, update, delete on public.cart_items to authenticated;

create policy cart_items_select_own
  on public.cart_items
  for select
  to authenticated
  using ((select auth.uid()) = user_id);

create policy cart_items_insert_own
  on public.cart_items
  for insert
  to authenticated
  with check ((select auth.uid()) = user_id);

create policy cart_items_update_own
  on public.cart_items
  for update
  to authenticated
  using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);

create policy cart_items_delete_own
  on public.cart_items
  for delete
  to authenticated
  using ((select auth.uid()) = user_id);

-- orders: only permanent (non-anonymous) users can place orders and read their own
grant select, insert on public.orders to authenticated;

create policy orders_select_own_permanent
  on public.orders
  for select
  to authenticated
  using (
    (select auth.uid()) = user_id
    and coalesce(((select auth.jwt()) ->> 'is_anonymous')::boolean, false) = false
  );

create policy orders_insert_own_permanent
  on public.orders
  for insert
  to authenticated
  with check (
    (select auth.uid()) = user_id
    and coalesce(((select auth.jwt()) ->> 'is_anonymous')::boolean, false) = false
  );
