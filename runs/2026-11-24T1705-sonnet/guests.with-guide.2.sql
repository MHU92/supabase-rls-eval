-- Enable RLS on all tables
alter table public.products enable row level security;
alter table public.cart_items enable row level security;
alter table public.orders enable row level security;

-- Remove default grants from client roles
revoke all on table public.products from anon, authenticated;
revoke all on table public.cart_items from anon, authenticated;
revoke all on table public.orders from anon, authenticated;

-- Grant back only what each role needs
grant select on table public.products to anon, authenticated;
grant select, insert, update, delete on table public.cart_items to authenticated;
grant select, insert on table public.orders to authenticated;

-- products: public read (signed-out visitors and signed-in users)
create policy "Anyone can browse products"
on public.products for select
to anon, authenticated
using ( true );

-- cart_items: signed-in users (including anonymous) manage their own cart
create policy "Users can view their own cart"
on public.cart_items for select
to authenticated
using ( (select auth.uid()) = user_id );

create policy "Users can add to their own cart"
on public.cart_items for insert
to authenticated
with check ( (select auth.uid()) = user_id );

create policy "Users can update their own cart"
on public.cart_items for update
to authenticated
using ( (select auth.uid()) = user_id )
with check ( (select auth.uid()) = user_id );

create policy "Users can delete from their own cart"
on public.cart_items for delete
to authenticated
using ( (select auth.uid()) = user_id );

-- orders: only permanent (non-anonymous) users can place and read their own orders
create policy "Permanent users can view their own orders"
on public.orders for select
to authenticated
using (
  (select auth.uid()) = user_id
  and coalesce(((select auth.jwt()) ->> 'is_anonymous')::boolean, false) = false
);

create policy "Permanent users can place their own orders"
on public.orders for insert
to authenticated
with check (
  (select auth.uid()) = user_id
  and coalesce(((select auth.jwt()) ->> 'is_anonymous')::boolean, false) = false
);

-- Indexes on columns used by policies
create index cart_items_user_id_idx on public.cart_items using btree (user_id);
create index orders_user_id_idx on public.orders using btree (user_id);
