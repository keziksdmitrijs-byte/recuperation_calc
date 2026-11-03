-- =====================================================================
--  Rekuperācijas kalkulators — Supabase setup
--  Run once in Supabase → SQL Editor. Safe to re-run.
--  No prices here: the catalogue (price-list prices + mark-ups) is loaded
--  separately (calc_seed.sql, not stored in git) or via the admin panel.
-- =====================================================================

-- ---------- 1. Administrators ----------------------------------------
create table if not exists public.calc_admins (
  user_id    uuid primary key references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);
alter table public.calc_admins enable row level security;
drop policy if exists "calc_admins: read own" on public.calc_admins;
create policy "calc_admins: read own" on public.calc_admins
  for select to authenticated using (user_id = auth.uid());

create or replace function public.calc_is_admin()
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.calc_admins where user_id = auth.uid());
$$;
revoke all on function public.calc_is_admin() from public;
grant execute on function public.calc_is_admin() to anon, authenticated;

-- ---------- 2. Catalogue: price-list prices + mark-ups (admin only) --
create table if not exists public.calc_catalog (
  id         int primary key default 1 check (id = 1),
  data       jsonb not null,
  updated_at timestamptz not null default now()
);
alter table public.calc_catalog enable row level security;
drop policy if exists "calc_catalog: admin" on public.calc_catalog;
create policy "calc_catalog: admin" on public.calc_catalog
  for all to authenticated using (public.calc_is_admin()) with check (public.calc_is_admin());
revoke all on public.calc_catalog from anon;
grant select, insert, update, delete on public.calc_catalog to authenticated;

-- What clients get: final prices (price × (1 + mark-up%)), no list prices, no mark-ups.
create or replace function public.calc_public_catalog()
returns jsonb language sql stable security definer set search_path = public as $$
  select jsonb_build_object(
    'settings', coalesce((
        select jsonb_object_agg(s.key, s.value)
        from jsonb_each(c.data -> 'settings') s
        where left(s.key, 4) <> 'adj_'), '{}'::jsonb),
    'items', coalesce((
        select jsonb_agg(
                 i.value || jsonb_build_object('price', round(
                   coalesce((i.value ->> 'price')::numeric, 0)
                   * (1 + coalesce((c.data -> 'settings' ->> ('adj_' || (i.value ->> 'type')))::numeric, 0) / 100), 2))
                 order by i.ordinality)
        from jsonb_array_elements(c.data -> 'items') with ordinality i), '[]'::jsonb),
    'updated_at', c.updated_at)
  from public.calc_catalog c
  where c.id = 1;
$$;
revoke all on function public.calc_public_catalog() from public;
grant execute on function public.calc_public_catalog() to anon, authenticated;

-- ---------- 3. Client calculations (saved when the client downloads the PDF)
create table if not exists public.calc_leads (
  id         bigint generated always as identity primary key,
  created_at timestamptz not null default now(),
  lang       text,
  client     jsonb,   -- name, phone, email, address
  summary    jsonb,   -- area, volume, required airflow, unit, duct checks, notes
  estimate   jsonb,   -- lines with final prices, totals
  plans      jsonb,   -- [{floor, img (jpeg data URL)}]
  status     text not null default 'new' check (status in ('new', 'done'))
);
create index if not exists calc_leads_created_idx on public.calc_leads (created_at desc);
alter table public.calc_leads enable row level security;
drop policy if exists "calc_leads: anyone can submit" on public.calc_leads;
create policy "calc_leads: anyone can submit" on public.calc_leads
  for insert to anon, authenticated
  with check (
    status = 'new'
    and coalesce(pg_column_size(client), 0)   < 20000
    and coalesce(pg_column_size(summary), 0)  < 100000
    and coalesce(pg_column_size(estimate), 0) < 300000
    and coalesce(pg_column_size(plans), 0)    < 4000000);
drop policy if exists "calc_leads: admin read" on public.calc_leads;
create policy "calc_leads: admin read" on public.calc_leads
  for select to authenticated using (public.calc_is_admin());
drop policy if exists "calc_leads: admin update" on public.calc_leads;
create policy "calc_leads: admin update" on public.calc_leads
  for update to authenticated using (public.calc_is_admin()) with check (public.calc_is_admin());
drop policy if exists "calc_leads: admin delete" on public.calc_leads;
create policy "calc_leads: admin delete" on public.calc_leads
  for delete to authenticated using (public.calc_is_admin());
revoke all on public.calc_leads from anon;
grant insert (lang, client, summary, estimate, plans) on public.calc_leads to anon;
grant select, insert, update, delete on public.calc_leads to authenticated;

-- ---------- 4. Make yourself an administrator --------------------------
-- First create the user: Supabase → Authentication → Users → Add user
-- (e-mail + password, tick "Auto Confirm User"). Then put that e-mail below and run:
--
-- insert into public.calc_admins (user_id)
--   select id from auth.users where email = 'your-admin@email.lv'
--   on conflict do nothing;
