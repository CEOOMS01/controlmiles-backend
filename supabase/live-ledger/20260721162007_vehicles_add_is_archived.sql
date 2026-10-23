-- BUG FIX (pedido explícito): deleteVehicle() hacía un DELETE físico sobre
-- `vehicles`. sessions.vehicle_id tiene FK ON DELETE SET NULL hacia esta
-- tabla, así que borrar un vehículo dejaba en null la referencia de TODOS
-- los viajes históricos que lo usaron — pérdida de dato real para reportes
-- de 3+ años ante el IRS. Se agrega is_archived: "eliminar" en la UI pasa a
-- ser un UPDATE (archivar), nunca un DELETE. La fila y el historial que la
-- referencia quedan intactos para siempre.
alter table public.vehicles
  add column if not exists is_archived boolean not null default false;

comment on column public.vehicles.is_archived is
  'Vehículo archivado por el usuario ("eliminado" desde la UI). Nunca se hace DELETE físico de vehicles para no romper sessions.vehicle_id (FK ON DELETE SET NULL) en viajes históricos.';
