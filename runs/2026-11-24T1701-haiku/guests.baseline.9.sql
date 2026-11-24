begin;

-- Remove Supabase's default broad grants so RLS is the only gate.
revoke all on public.products   from anon, authenticated;
revoke all on public.cart_items from anon, authenticated;
revoke all on public.orders     from anon, authenticated;

-- Grant only what each role needs. RLS policies below narrow the rows.
grant select on public.products to anon, authenticated;
grant select, insert, update, delete on public.cart_items to authenticated;
grant select, insert on public.orders to authenticated;

alter table public.products   enable row level security;
alter table public.cart_items enable row level security;
alter table public.orders     enable row level security;

-- products: anyone (including signed-out visitors) can browse. No client writes.
create policy products_select_public
  on public.products
  for select
  to anon, authenticated
  using (true);

-- cart_items: any signed-in user, anonymous or permanent, manages only their own rows.
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

-- orders: only permanent (non-anonymous) users can read their own orders and place new ones.
-- No update or delete policies, so orders cannot be modified or removed by clients.
create policy orders_select_own_permanent
  on public.orders
  for select
  to authenticated
  using (
    (select auth.uid()) = user_id
    and coalesce((select auth.jwt()->>'is_anonymous')::boolean, false) = false
  );

create policy orders_insert_own_permanent
  on public.orders
  for insert
  to authenticated
  with check (
    (select auth.uid()) = user_id
    and coalesce((select auth.jwt()->>'is_anonymous')::boolean, false) = false
  );

commit;
