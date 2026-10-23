select cron.alter_job(
  (select jobid from cron.job where jobname = 'ifta-quarterly-rate-sync'),
  schedule := '0 6 1-10 1,4,7,10 *'
);
