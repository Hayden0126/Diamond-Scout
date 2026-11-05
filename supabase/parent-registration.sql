-- Run this migration in the Supabase SQL Editor before using parent check-in.
create table if not exists public.registration_submissions (
 id uuid primary key default gen_random_uuid(),
 first_name text not null check (length(trim(first_name)) between 1 and 70),
 last_name text not null check (length(trim(last_name)) between 1 and 70),
 division text not null check (division in ('9u','10u')),
 positions text not null check (length(trim(positions)) between 1 and 120),
 status text not null default 'pending' check (status in ('pending','approved','rejected')),
 player_id uuid references public.players(id),
 approved_by uuid,
 approved_at timestamptz,
 created_at timestamptz not null default now()
);
create index if not exists ds_registration_queue_idx on public.registration_submissions(division,status,created_at);
alter table public.registration_submissions enable row level security;
revoke all on public.registration_submissions from anon, authenticated;
grant insert (first_name,last_name,division,positions) on public.registration_submissions to anon;
grant select on public.registration_submissions to authenticated;
drop policy if exists "Public registration submissions" on public.registration_submissions;
create policy "Public registration submissions" on public.registration_submissions for insert to anon with check (status='pending' and player_id is null and approved_by is null and approved_at is null);
drop policy if exists "Coach registration queue" on public.registration_submissions;
create policy "Coach registration queue" on public.registration_submissions for select to authenticated using (public.ds_player_visible(division));

create or replace function public.ds_approve_registration(registration_id uuid)
returns text language plpgsql security definer set search_path=''
as $$
declare r public.registration_submissions%rowtype; coach_role text; candidate text; new_player uuid; i int;
begin
 select role into coach_role from public.coach_profiles where user_id=auth.uid();
 if coach_role not in ('coach','assistant_coach','head_coach','manager') then raise exception 'Coach permission required'; end if;
 select * into r from public.registration_submissions where id=registration_id for update;
 if not found or not public.ds_player_visible(r.division) then raise exception 'Registration not found or inaccessible'; end if;
 if r.status='approved' then return 'already_approved'; end if;
 if r.status<>'pending' then return r.status; end if;
 perform pg_catalog.pg_advisory_xact_lock(2026,1105);
 for i in 1..150 loop
  candidate=(1000+floor(random()*9000)::int)::text;
  if exists(select 1 from public.players where number::text=candidate) then continue; end if;
  begin
   insert into public.players(name,number,positions,division)
   values(trim(r.first_name)||' '||trim(r.last_name),candidate,r.positions,r.division)
   returning id into new_player;
   exit;
  exception when unique_violation then new_player=null;
  end;
 end loop;
 if new_player is null then raise exception 'Unable to allocate tryout number'; end if;
 update public.registration_submissions set status='approved',player_id=new_player,approved_by=auth.uid(),approved_at=now() where id=r.id;
 return 'approved';
end $$;
revoke all on function public.ds_approve_registration(uuid) from public,anon;
grant execute on function public.ds_approve_registration(uuid) to authenticated;

create or replace function public.ds_reject_registration(registration_id uuid)
returns text language plpgsql security definer set search_path=''
as $$
declare r public.registration_submissions%rowtype; coach_role text;
begin
 select role into coach_role from public.coach_profiles where user_id=auth.uid();
 if coach_role not in ('coach','assistant_coach','head_coach','manager') then raise exception 'Coach permission required'; end if;
 select * into r from public.registration_submissions where id=registration_id for update;
 if not found or not public.ds_player_visible(r.division) then raise exception 'Registration not found or inaccessible'; end if;
 if r.status<>'pending' then return r.status; end if;
 update public.registration_submissions set status='rejected' where id=r.id;
 return 'rejected';
end $$;
revoke all on function public.ds_reject_registration(uuid) from public,anon;
grant execute on function public.ds_reject_registration(uuid) to authenticated;
