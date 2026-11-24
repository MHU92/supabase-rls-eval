alter table public.products enable row level security;
alter table public.cart_items enable row level security;
alter table public.orders enable row level security;
revoke insert, update, delete, truncate on public.products from anon, authenticated;
revoke all on public.cart_items, public.orders from anon;

create policy "products: everyone browses" on public.products for select to anon, authenticated using (true);
create policy "cart: own items" on public.cart_items for all to authenticated
  using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
-- Anonymous sign-ins use the authenticated role too; the is_anonymous claim tells them apart.
create policy "orders: permanent users read own" on public.orders for select to authenticated
  using ((select auth.uid()) = user_id and (select (auth.jwt() ->> 'is_anonymous')::boolean) is false);
create policy "orders: permanent users place" on public.orders for insert to authenticated
  with check ((select auth.uid()) = user_id and (select (auth.jwt() ->> 'is_anonymous')::boolean) is false);
