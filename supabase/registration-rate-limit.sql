-- DiamondScout registration rate-limit migration.
-- Run AFTER deploying and testing the submit-registration Edge Function.
-- Keeps existing registration rows, players, and evaluations intact.

create table if not exists public.ds_registration_rate_events (
  id bigint generated always as identity primary key,
  client_hash text not null,
  created_at timestamptz not null default now()
);
create index if not exists ds_registration_rate_events_lookup
  on public.ds_registration_rate_events(client_hash, created_at);
alter table public.ds_registration_rate_events enable row level security;
revoke all on public.ds_registration_rate_events from anon, authenticated;
-- No client-facing RLS policies: only the service role uses this table.

create or replace function public.ds_submit_registration(
  p_first_name text,
  p_last_name text,
  p_division text,
  p_positions text,
  p_client_hash text
)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  new_id uuid;
  recent_count integer;
begin
  if auth.role() <> 'service_role' then
    raise exception 'Server-only registration endpoint';
  end if;
  if length(btrim(coalesce(p_first_name,''))) not between 1 and 70
     or length(btrim(coalesce(p_last_name,''))) not between 1 and 70
     or p_division not in ('9u','10u')
     or length(btrim(coalesce(p_client_hash,''))) <> 64
     or p_client_hash !~ '^[0-9a-f]{64}$'
     or length(btrim(coalesce(p_positions,''))) not between 1 and 120
     or exists (
       select 1 from unnest(string_to_array(p_positions,',')) as pos
       where btrim(pos) not in ('P','C','1B','2B','SS','3B','LF','CF','RF')
     )
     or array_length(string_to_array(p_positions,','),1) > 9
  then
    raise exception 'Invalid registration details';
  end if;

  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext(p_client_hash));

  select count(*) into recent_count
  from public.ds_registration_rate_events
  where client_hash=p_client_hash
    and created_at > now() - interval '10 minutes';

  if recent_count >= 5 then
    raise exception 'REGISTRATION_RATE_LIMIT';
  end if;

  insert into public.registration_submissions(first_name,last_name,division,positions)
  values (btrim(p_first_name),btrim(p_last_name),p_division,p_positions)
  returning id into new_id;

  insert into public.ds_registration_rate_events(client_hash)
  values (p_client_hash);

  return new_id;
end;
$$;

revoke all on function public.ds_submit_registration(text,text,text,text,text)
  from public,anon,authenticated;
grant execute on function public.ds_submit_registration(text,text,text,text,text)
  to service_role;

-- IMPORTANT: execute the following only AFTER the Edge Function is deployed
-- and register.html has been switched to use it.
-- revoke insert (first_name,last_name,division,positions)
--   on public.registration_submissions from anon;
-- drop policy if exists "Public registration submissions"
--   on public.registration_submissions;
