# Routing server (Valhalla)

Road path and leg times for school routes, computed by **our own server** so the
stops (children's homes) never go to a third party.

## What it costs and needs
- One small cloud server, about 8-9 USD a month (a Hetzner CX32 in Ashburn: 4 GB
  RAM, 80 GB disk was the reference). Flat: it does not grow per customer.
- Tiles per state are built once; Maryland alone is small. Add the states of
  your customers in `TILE_URLS` (comma separated Geofabrik `.osm.pbf` links). A
  whole-US build was NOT measured: do it state by state.
- The web app asks it once when a route's stops are saved (not on every page
  view), so the traffic is tiny.

## Install on the server
1. Create the server (Ubuntu), install Docker (`curl -fsSL https://get.docker.com | sh`).
2. Point a DNS name (e.g. `routes.controlmiles.com`) at it. Open ports 22, 80, 443 only.
3. Copy this folder, then create `.env` next to `docker-compose.yml`:
   ```
   ROUTING_HOST=routes.controlmiles.com
   ROUTING_KEY=<long random secret>
   TILE_URLS=https://download.geofabrik.de/north-america/us/maryland-latest.osm.pbf,https://download.geofabrik.de/north-america/us/district-of-columbia-latest.osm.pbf
   ```
4. `docker compose up -d` (the first start downloads the maps and builds the
   tiles; it can take several minutes; `docker compose logs -f valhalla`).
5. In Vercel (Production) set `ROUTING_URL=https://routes.controlmiles.com` and
   `ROUTING_KEY=<the same secret>`, then redeploy. In the panel, a route page
   has a "Draw the road path" button for routes created before.

## Keep it fresh
Once a month: `docker compose pull && FORCE_REBUILD=True docker compose up -d`
(or delete `./data/valhalla_tiles*` and restart) to pick up new OpenStreetMap data.

## Test it
```
curl -s https://routes.controlmiles.com/status -H "X-CM-Key: $ROUTING_KEY"
curl -s https://routes.controlmiles.com/route -H "X-CM-Key: $ROUTING_KEY" -d '{"locations":[{"lat":39.3317,"lon":-76.6296},{"lat":39.2904,"lon":-76.6122}],"costing":"auto"}'
```
Local test without HTTPS: `docker compose -f docker-compose.local.yml up`, then
`http://127.0.0.1:8002/status`.
