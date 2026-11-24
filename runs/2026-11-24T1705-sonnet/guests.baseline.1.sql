-- Enable RLS on all tables
alter table public.products enable row level security;
alter table public.cart_items enable row level security;
alter table public.orders enable row level security;

-- Remove default broad grants, then grant only what is needed
revoke all on public.products from anon, authenticated;
revoke all on public.cart_items from anon, authenticated;
revoke all on public.orders from anon, authenticated;

grant select on public.products to anon, authenticated;
grant select, insert, update, delete on public.cart_items to authenticated;
grant select, insert on public.orders to authenticated;

-- products: public read access (signed-out visitors and all signed-in users)
create policy "products are publicly readable"
  on public.products
  for select
  to anon, authenticated
  using (true);

-- cart_items: signed-in users (including anonymous) manage their own cart
create policy "users can view own cart"
  on public.cart_items
  for select
  to authenticated
  using (user_id = (select auth.uid()));

create policy "users can add to own cart"
  on public.cart_items
  for insert
  to authenticated
  with check (user_id = (select auth.uid()));

create policy "users can update own cart"
  on public.cart_items
  for update
  to authenticated
  using (user_id = (select auth.uid()))
  with check (user_id = (select auth.uid()));

create policy "users can delete from own cart"
  on public.cart_items
  for delete
  to authenticated
  using (user_id = (select auth.uid()));

-- orders: only permanent (non-anonymous) users can place and read their own orders
create policy "permanent users can view own orders"
  on public.orders
  for select
  to authenticated
  using (
    user_id = (select auth.uid())
    and coalesce(((select auth.jwt()) ->> 'is_anonymous')::boolean, false) = false
  );

create policy "permanent users can place own orders"
  on public.orders
  for insert
  to authenticated
  with check (
    user_id = (select auth.uid())
    and coalesce(((select auth.jwt()) ->> 'is_anonymous')::boolean, false) = false
  );
