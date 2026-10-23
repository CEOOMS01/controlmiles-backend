ALTER TABLE public.sessions
  ADD COLUMN IF NOT EXISTS cgc_decision_id text,
  ADD COLUMN IF NOT EXISTS cgc_sealed_at timestamptz;
