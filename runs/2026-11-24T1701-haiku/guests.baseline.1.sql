begin;

-- Enable RLS on all three tables
alter table public.products enable row level security;
alter table public.cart_items enable row level security;
alter table public.orders enable row level security;

-- Drop Supabase's default grants and re-grant only what the access rule needs
revoke all on public.products from anon, authenticated;
revoke all on public.cart_items from anon, authenticated;
revoke all on public.orders from anon, authenticated;

grant select on public.products to anon, authenticated;
grant select, insert, update, delete on public.cart_items to authenticated;
grant select, insert on public.orders to authenticated;

-- products: anyone (including signed-out visitors) can browse
create policy products_select_public
  on public.products
  for select
  to anon, authenticated
  using (true);

-- cart_items: any signed-in user (anonymous or permanent) manages only their own cart
create policy cart_items_own_rows
  on public.cart_items
  for all
  to authenticated
  using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);

-- orders: only permanent (non-anonymous) users, and only their own rows.
-- A missing is_anonymous claim is treated as anonymous (denied).
create policy orders_select_own_permanent
  on public.orders
  for select
  to authenticated
  using (
    (select auth.uid()) = user_id
    and coalesce((auth.jwt() ->> 'is_anonymous')::boolean, true) = false
  );

create policy orders_insert_own_permanent
  on public.orders
  for insert
  to authenticated
  with check (
    (select auth.uid()) = user_id
    and coalesce((auth.jwt() ->> 'is_anonymous')::boolean, true) = false
  );

commit;
