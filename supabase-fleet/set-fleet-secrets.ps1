# Pone las claves de terceros en el proyecto Supabase de Fleet.
# Tu escribes cada valor en esta terminal (no se ve en pantalla); nadie mas lo lee.
# Deja una linea vacia para saltarte una clave. Se guardan en Supabase como secretos de las edge functions.
#
# Requiere haber hecho `supabase login` con la cuenta que tiene ControlMiles Fleet.

$ref = 'oweekkdectvsigspyafu'

function Set-FleetSecret([string]$name, [string]$help) {
    Write-Host ''
    Write-Host "$name  -  $help" -ForegroundColor Cyan
    $secure = Read-Host -Prompt "Valor (vacio = saltar)" -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try { $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    if ([string]::IsNullOrWhiteSpace($plain)) { Write-Host 'Saltada.'; return }
    supabase secrets set "$name=$plain" --project-ref $ref 2>&1 | Select-String -Pattern 'Finished|error' | ForEach-Object { $_.Line }
}

Set-FleetSecret 'STRIPE_SECRET_KEY' 'Stripe > Developers > API keys > Secret key (sk_live_... o sk_test_...)'
Set-FleetSecret 'STRIPE_WEBHOOK_SECRET' 'Stripe > Webhooks: crea un endpoint nuevo a https://oweekkdectvsigspyafu.supabase.co/functions/v1/stripe-webhook y copia su Signing secret (whsec_...)'
Set-FleetSecret 'RESEND_API_KEY' 'Resend > API Keys (re_...), para invitaciones y recordatorios'
Set-FleetSecret 'TURNSTILE_SECRET' 'Cloudflare Turnstile > secret key del sitio de inscripcion publica'
Set-FleetSecret 'SITE_URL' 'Direccion publica de la web de Fleet, por ejemplo https://controlmiles.com'

Write-Host ''
Write-Host 'Secretos que existen ahora en Fleet (solo nombres):' -ForegroundColor Green
supabase secrets list --project-ref $ref 2>&1 | Select-String -Pattern '^\s*[A-Z_]+\s*\|' | ForEach-Object { $_.Line }
