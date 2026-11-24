-- Products: public catalog. Everyone (signed-out and signed-in) reads, nobody writes.
alter table public.products enable row level security;
revoke all on table public.products from anon, authenticated;
grant select on table public.products to anon, authenticated;

create policy "Anyone can browse products"
on public.products for select
to anon, authenticated
using ( true );

-- Cart: any signed-in user, including anonymous ones, manages only their own rows.
alter table public.cart_items enable row level security;
revoke all on table public.cart_items from anon, authenticated;
grant select, insert, update, delete on table public.cart_items to authenticated;

create policy "Users read their own cart items"
on public.cart_items for select
to authenticated
using ( (select auth.uid()) = user_id );

create policy "Users add to their own cart"
on public.cart_items for insert
to authenticated
with check ( (select auth.uid()) = user_id );

create policy "Users update their own cart items"
on public.cart_items for update
to authenticated
using ( (select auth.uid()) = user_id )
with check ( (select auth.uid()) = user_id );

create policy "Users remove their own cart items"
on public.cart_items for delete
to authenticated
using ( (select auth.uid()) = user_id );

create index if not exists cart_items_user_id_idx
on public.cart_items using btree (user_id);

-- Orders: only permanent (non-anonymous) users can place and read their own orders.
-- The is_anonymous check fails closed: a missing claim denies access.
alter table public.orders enable row level security;
revoke all on table public.orders from anon, authenticated;
grant select, insert on table public.orders to authenticated;

create policy "Permanent users read their own orders"
on public.orders for select
to authenticated
using (
  (select auth.uid()) = user_id
  and (select auth.jwt() ->> 'is_anonymous') = 'false'
);

create policy "Permanent users place their own orders"
on public.orders for insert
to authenticated
with check (
  (select auth.uid()) = user_id
  and (select auth.jwt() ->> 'is_anonymous') = 'false'
);

create index if not exists orders_user_id_idx
on public.orders using btree (user_id);
