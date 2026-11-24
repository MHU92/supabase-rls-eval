begin;

-- products: public read-only for anonymous and signed-in visitors
alter table public.products enable row level security;
revoke all on public.products from anon, authenticated;
grant select on public.products to anon, authenticated;

create policy products_select_public
  on public.products
  for select
  to anon, authenticated
  using (true);

-- cart_items: every signed-in user (including anonymous) manages only their own rows
alter table public.cart_items enable row level security;
revoke all on public.cart_items from anon, authenticated;
grant select, insert, update, delete on public.cart_items to authenticated;

create policy cart_items_owner_all
  on public.cart_items
  for all
  to authenticated
  using (user_id = (select auth.uid()))
  with check (user_id = (select auth.uid()));

-- orders: only permanent (non-anonymous) users, and only their own orders
alter table public.orders enable row level security;
revoke all on public.orders from anon, authenticated;
grant select, insert on public.orders to authenticated;

create policy orders_select_own_permanent
  on public.orders
  for select
  to authenticated
  using (
    user_id = (select auth.uid())
    and (select auth.jwt()->>'is_anonymous') = 'false'
  );

create policy orders_insert_own_permanent
  on public.orders
  for insert
  to authenticated
  with check (
    user_id = (select auth.uid())
    and (select auth.jwt()->>'is_anonymous') = 'false'
  );

commit;
