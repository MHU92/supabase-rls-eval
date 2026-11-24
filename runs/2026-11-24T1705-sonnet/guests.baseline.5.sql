-- Enable RLS
alter table public.products   enable row level security;
alter table public.cart_items enable row level security;
alter table public.orders     enable row level security;

-- Tighten default grants (least privilege)
revoke all on public.products   from anon, authenticated;
revoke all on public.cart_items from anon, authenticated;
revoke all on public.orders     from anon, authenticated;

grant select on public.products to anon, authenticated;
grant select, insert, update, delete on public.cart_items to authenticated;
grant select, insert on public.orders to authenticated;

-- products: public read-only catalog
create policy "products are publicly readable"
  on public.products
  for select
  to anon, authenticated
  using (true);

-- cart_items: signed-in users (including anonymous) manage their own cart
create policy "users select own cart"
  on public.cart_items
  for select
  to authenticated
  using (user_id = (select auth.uid()));

create policy "users insert own cart"
  on public.cart_items
  for insert
  to authenticated
  with check (user_id = (select auth.uid()));

create policy "users update own cart"
  on public.cart_items
  for update
  to authenticated
  using (user_id = (select auth.uid()))
  with check (user_id = (select auth.uid()));

create policy "users delete own cart"
  on public.cart_items
  for delete
  to authenticated
  using (user_id = (select auth.uid()));

-- orders: only permanent (non-anonymous) users can read and place their own orders
create policy "permanent users select own orders"
  on public.orders
  for select
  to authenticated
  using (
    user_id = (select auth.uid())
    and coalesce(((select auth.jwt()) ->> 'is_anonymous')::boolean, false) = false
  );

create policy "permanent users insert own orders"
  on public.orders
  for insert
  to authenticated
  with check (
    user_id = (select auth.uid())
    and coalesce(((select auth.jwt()) ->> 'is_anonymous')::boolean, false) = false
  );
