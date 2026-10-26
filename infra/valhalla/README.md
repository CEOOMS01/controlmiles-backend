# Routing server (Valhalla)

Road path and leg times for school routes, computed by **our own server** so the
stops (children's homes) never go to a third party.

## What it costs and needs
- One small cloud server, about 8-9 USD a month (a Hetzner CX32 in Ashburn: 4 GB
  RAM, 80 GB disk was the reference). Flat: it does not grow per customer.
- Tiles per state are built once (Maryland: a 206 MB map). Add the states of your
  customers as `.pbf` files in `./data`. A whole-US build was NOT measured: do it
  state by state.
- The web app asks it once when a route's stops are saved (not on every page
  view), so the traffic is tiny.

## Install on the server
1. Create the server (Ubuntu), install Docker (`curl -fsSL https://get.docker.com | sh`).
2. Point a DNS name (e.g. `routes.controlmiles.com`) at it. Open ports 22, 80, 443 only.
3. Copy this folder, then create `.env` next to `docker-compose.yml`:
   ```
   ROUTING_HOST=routes.controlmiles.com
   ROUTING_KEY=<long random secret>
   ```
4. Download the maps of your customers' states into `./data` (Geofabrik's
   "latest" links REDIRECT to a dated file, so use `curl -L`; the image's own
   downloader does not follow redirects):
   ```
   mkdir -p data
   curl -L --fail -o data/maryland.osm.pbf https://download.geofabrik.de/north-america/us/maryland-latest.osm.pbf
   curl -L --fail -o data/district-of-columbia.osm.pbf https://download.geofabrik.de/north-america/us/district-of-columbia-latest.osm.pbf
   ```
   Then `docker compose up -d`: the first start builds the tiles from every
   `.pbf` in `./data` (Maryland took a few minutes on 2 threads; follow it with
   `docker compose logs -f valhalla`).
5. In Vercel (Production) set `ROUTING_URL=https://routes.controlmiles.com` and
   `ROUTING_KEY=<the same secret>`, then redeploy. In the panel, a route page
   has a "Draw the road path" button for routes created before.

## Keep it fresh
Once a month: download the `.pbf` files again (step 4), delete `./data/valhalla_tiles*`
and run `docker compose up -d` to rebuild the tiles with new OpenStreetMap data.

## Test it
```
curl -s https://routes.controlmiles.com/status -H "X-CM-Key: $ROUTING_KEY"
curl -s https://routes.controlmiles.com/route -H "X-CM-Key: $ROUTING_KEY" -d '{"locations":[{"lat":39.3317,"lon":-76.6296},{"lat":39.2904,"lon":-76.6122}],"costing":"auto"}'
```
Local test without HTTPS: `docker compose -f docker-compose.local.yml up`, then
`http://127.0.0.1:8002/status`.
