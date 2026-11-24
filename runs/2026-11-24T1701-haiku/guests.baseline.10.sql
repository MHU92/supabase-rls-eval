-- Access rule migration: anonymous sign-ins, cart, and permanent-only orders

-- 1. Enable RLS (without policies, all access is denied by default)
alter table public.products   enable row level security;
alter table public.cart_items enable row level security;
alter table public.orders     enable row level security;

-- 2. Remove Supabase's default grants so only explicitly granted privileges remain
revoke all on public.products   from anon, authenticated;
revoke all on public.cart_items from anon, authenticated;
revoke all on public.orders     from anon, authenticated;

-- 3. Grant only what the access rule needs
grant select on public.products to anon, authenticated;
grant select, insert, update, delete on public.cart_items to authenticated;
grant select, insert on public.orders to authenticated;

-- 4. Products: publicly readable by everyone, including signed-out visitors
create policy "products_select_public"
  on public.products
  for select
  to anon, authenticated
  using (true);

-- 5. Cart: any signed-in user (anonymous or permanent) manages only their own rows
create policy "cart_items_select_own"
  on public.cart_items
  for select
  to authenticated
  using (user_id = auth.uid());

create policy "cart_items_insert_own"
  on public.cart_items
  for insert
  to authenticated
  with check (user_id = auth.uid());

create policy "cart_items_update_own"
  on public.cart_items
  for update
  to authenticated
  using (user_id = auth.uid())
  with check (user_id = auth.uid());

create policy "cart_items_delete_own"
  on public.cart_items
  for delete
  to authenticated
  using (user_id = auth.uid());

-- 6. Orders: only permanent (non-anonymous) users can place and read their own orders
create policy "orders_select_own_permanent"
  on public.orders
  for select
  to authenticated
  using (
    user_id = auth.uid()
    and (auth.jwt() ->> 'is_anonymous') is distinct from 'true'
  );

create policy "orders_insert_own_permanent"
  on public.orders
  for insert
  to authenticated
  with check (
    user_id = auth.uid()
    and (auth.jwt() ->> 'is_anonymous') is distinct from 'true'
  );
