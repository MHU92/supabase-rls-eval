begin;

-- Products: public catalog, read-only for everyone (signed-out and signed-in).
alter table public.products enable row level security;
revoke all on public.products from anon, authenticated;
grant select on public.products to anon, authenticated;

create policy products_select_public
  on public.products
  for select
  to anon, authenticated
  using (true);

-- Cart items: any signed-in user (including anonymous) manages only their own rows.
-- Signed-out visitors have no access.
alter table public.cart_items enable row level security;
revoke all on public.cart_items from anon, authenticated;
grant select, insert, update, delete on public.cart_items to authenticated;

create policy cart_items_own_rows
  on public.cart_items
  for all
  to authenticated
  using (user_id = (select auth.uid()))
  with check (user_id = (select auth.uid()));

-- Orders: only permanent (non-anonymous) users can create and read their own orders.
-- Missing or non-'false' is_anonymous claim denies access.
alter table public.orders enable row level security;
revoke all on public.orders from anon, authenticated;
grant select, insert on public.orders to authenticated;

create policy orders_select_own_permanent
  on public.orders
  for select
  to authenticated
  using (
    user_id = (select auth.uid())
    and (select auth.jwt() ->> 'is_anonymous') = 'false'
  );

create policy orders_insert_own_permanent
  on public.orders
  for insert
  to authenticated
  with check (
    user_id = (select auth.uid())
    and (select auth.jwt() ->> 'is_anonymous') = 'false'
  );

commit;
