
alter function public.generate_report_access_code(date, date, uuid) set search_path = public, extensions;
alter function public.redeem_report_access_code(text, text) set search_path = public, extensions;
