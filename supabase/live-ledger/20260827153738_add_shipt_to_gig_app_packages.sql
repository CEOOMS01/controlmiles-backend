insert into public.gig_app_packages (gig_app_id, os, package_name)
values ('shipt', 'android', 'com.shipt.shopper')
on conflict do nothing;
