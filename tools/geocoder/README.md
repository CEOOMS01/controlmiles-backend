# ControlMiles own geocoder

U.S. address geocoder built on Census TIGER/Line address ranges (public domain).
Nothing leaves our infrastructure. Tested against the Census Geocoder on 22
Maryland addresses: median 7 m apart, max 8 m (a street-range interpolation, so
it is never rooftop-exact).

## Build every state (50 + DC + PR, ~1 GB, ~1 hour)
```
pip install pyshp
python build_all.py                  # resumable; writes out/geocode_<ST>.bin
```
Copy them as out/geocode/<ST>.bin and upload that folder to the R2 bucket
olimsysmaps (dashboard: Objects > Upload > drag the `geocode` folder), or with
wrangler:  `npx wrangler r2 object put olimsysmaps/geocode/MD.bin --file out/geocode/MD.bin --remote`
for each file. One state only:  `python build_state.py MD 24`.
The Census server sometimes rejects one county file for good ("Request
Rejected"); the builder then uses the 2024/2023/2022 release of that county.
Every file is read in small range requests; a state is 13 MB (Maryland) to a
few hundred MB. R2 has 10 GB free; the maps file already uses ~9 GB, beyond
that R2 charges cents per GB-month.

## Deploy the Worker
```
cd ../../infra/cloudflare/geocoder
npx wrangler login        # once; you authorize in the browser
npx wrangler deploy
```
Then in the web app (Vercel, Production) set `GEOCODER_URL` to the Worker URL
(`https://controlmiles-geocoder.<account>.workers.dev`) and, if you set the
secret, `GEOCODER_KEY`.

## Limits / next
- Street addresses only (number + street); no place names, no PO boxes.
- Several candidates when a street name repeats; a city or ZIP in the text narrows them.
- Rebuild yearly (new TIGER release) or when a customer's state is missing.
