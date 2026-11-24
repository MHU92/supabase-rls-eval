-- RLS for shop access rules: public catalog, per-user carts, permanent-user orders.

-- Remove Supabase's default table grants so access is limited to what is granted below.
revoke all on public.products, public.cart_items, public.orders from anon, authenticated;

-- products: readable by everyone, including signed-out visitors. No writes.
alter table public.products enable row level security;
grant select on public.products to anon, authenticated;

create policy "products_select_public"
  on public.products
  for select
  to anon, authenticated
  using (true);

-- cart_items: any signed-in user (anonymous or permanent) can manage only their own rows.
alter table public.cart_items enable row level security;
grant select, insert, update, delete on public.cart_items to authenticated;

create policy "cart_items_owner_all"
  on public.cart_items
  for all
  to authenticated
  using (user_id = (select auth.uid()))
  with check (user_id = (select auth.uid()));

-- orders: only permanent (non-anonymous) users, only their own orders.
-- Orders can be read and placed, but not updated or deleted by clients.
alter table public.orders enable row level security;
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
