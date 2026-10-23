-- ============================================================
-- FIX 1: uk_sessions_user_date bloqueaba múltiples viajes/día
-- ============================================================
alter table public.sessions drop constraint if exists uk_sessions_user_date;

-- ============================================================
-- FIX 2: un solo vehículo activo por usuario, blindado a nivel de schema
-- ============================================================
create unique index if not exists uk_vehicles_one_active_per_owner
  on public.vehicles (owner_user_id)
  where is_active = true and is_archived = false and owner_user_id is not null;

-- ============================================================
-- FIX 3 (regla nueva, pedida explícitamente): bloquear cambio de
-- vehículo activo mientras hay sesión sin cerrar
-- ============================================================
create or replace function public.fn_block_vehicle_switch_during_active_session()
returns trigger
language plpgsql
as $$
declare
  v_owner uuid;
  v_has_open_session boolean;
begin
  if tg_op = 'INSERT' then
    if new.is_active is distinct from true then
      return new;
    end if;
    v_owner := new.owner_user_id;
  elsif tg_op = 'UPDATE' then
    if new.is_active is not distinct from old.is_active then
      return new;
    end if;
    v_owner := coalesce(new.owner_user_id, old.owner_user_id);
  end if;

  if v_owner is null then
    return new;
  end if;

  select exists (
    select 1 from public.sessions
    where user_id = v_owner and is_closed = false
  ) into v_has_open_session;

  if v_has_open_session then
    raise exception 'No puedes cambiar de vehículo activo mientras tienes un viaje en curso. Termina el viaje actual primero.';
  end if;

  return new;
end;
$$;

drop trigger if exists tr_vehicles_block_switch_during_session on public.vehicles;
create trigger tr_vehicles_block_switch_during_session
  before insert or update on public.vehicles
  for each row
  execute function public.fn_block_vehicle_switch_during_active_session();

-- ============================================================
-- FIX 4: RPC atómico para reemplazar los dos updates secuenciales
-- ============================================================
create or replace function public.set_active_vehicle(p_vehicle_id uuid)
returns void
language plpgsql
security invoker
as $$
begin
  update public.vehicles
  set is_active = false, is_primary = false
  where owner_user_id = auth.uid()
    and is_archived = false
    and is_active = true;

  update public.vehicles
  set is_active = true, is_primary = true
  where id = p_vehicle_id
    and owner_user_id = auth.uid();
end;
$$;
