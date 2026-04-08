# Security Gateway

This project is a lightweight traffic-protection gateway designed to run on a Google Cloud VM. It watches traffic on the VM network interface, detects high packet-rate attack behavior, blocks the configured attacker IP at the host firewall level, and reports health or attack events to an external backend dashboard.

The backend is currently running locally and exposed to the VM through a temporary Cloudflare tunnel URL. Because that URL changes after backend restarts, the gateway reads the backend base URL from `.env` so it can be updated in one place.

## What the system does

- Monitors live traffic volume on the VM interface defined in `gateway_main.py`.
- Treats sustained packet spikes above the configured threshold as an attack.
- Blocks the attacker with Linux firewall rules and a blackhole route.
- Sends heartbeat and attack events to an external backend API.
- Starts with a fresh blocklist on every restart for testing and demos.

## Main runtime files

- `gateway_main.py`
  Main runtime loop. Reads interface packet counters, decides when traffic crosses the attack threshold, applies blocking, and resets runtime blocks on startup and shutdown.
- `core/firewall_manager.py`
  Sends heartbeat and attack notifications to the remote backend, using `BACKEND_BASE_URL` from `.env`.
- `core/ai_engine.py`
  Loads the trained model and feature list from the `models/` directory.
- `core/feature_extractor.py`
  Contains the packet-to-feature logic used by the AI side of the project.
- `config/vpn_config.py`
  Stores the WireGuard/VPN settings used by the wider system integration.
- `models/rf_ids_model.pkl`
  Trained prediction model.
- `models/feature_list.pkl`
  Feature order expected by the model.

## How traffic reaches this system

The gateway is intended to live on a Google Cloud VM that is reachable through WireGuard VPN.

1. A protected client connects to the VM over WireGuard.
2. The VM receives the traffic on its cloud network interface.
3. `gateway_main.py` watches that interface and measures packet rate.
4. If the rate crosses the configured threshold, the gateway blocks the configured attacker IP.
5. The gateway also notifies the external dashboard/backend so the other system can show live health or attack state.

## VPN relationship

This project does not create the full VPN by itself. It is one side of a larger system.

- The VM must already have WireGuard installed and configured.
- The VM must have its VPN interface and cloud routing working before the gateway starts.
- The `config/vpn_config.py` file keeps the expected VPN names and addressing aligned with the connected system.
- The other system connects through that VPN and exchanges traffic with this gateway over the private address space.

## What the other backend needs to do

The external backend is expected to expose an API endpoint that accepts gateway health and mitigation events.

Current gateway behavior:

- Base URL source: `.env` key `BACKEND_BASE_URL`
- Current local-backend tunnel URL: `https://ethics-hits-troubleshooting-sas.trycloudflare.com`
- Endpoint: `POST /api/alerts`
- Header: `X-Alert-Secret`
- JSON body during heartbeat:

```json
{
  "victim_vpn_ip": "10.0.0.12",
  "attacker_ip": "CLEAN"
}
```

- JSON body during attack:

```json
{
  "victim_vpn_ip": "10.0.0.12",
  "attacker_ip": "10.128.0.3"
}
```

The backend should:

- accept authenticated POST requests from the VM
- return `200` or `201` on success
- record health and attack state for the dashboard
- avoid returning large HTML error pages, because the gateway expects a machine-oriented API response

## Updating the Cloudflare tunnel URL

Because the backend is local right now, it is exposed with a temporary `trycloudflare.com` URL that changes whenever the backend tunnel restarts.

To update the gateway after the backend gets a new tunnel URL:

1. open `.env`
2. replace the value of `BACKEND_BASE_URL` with the new Cloudflare URL
3. save the file
4. restart the gateway process

Example:

```env
BACKEND_BASE_URL=https://new-random-name.trycloudflare.com
```

The gateway will then send alerts to:

```text
https://new-random-name.trycloudflare.com/api/alerts
```

## Test-mode behavior

This repo is currently configured for internal testing on cloud infrastructure.

- The attack source is set to `10.128.0.3` in `gateway_main.py`.
- That IP is blocked when the traffic threshold is exceeded.
- On every gateway restart, the runtime firewall block rules and blackhole routes are cleared so each test starts fresh.

This startup cleanup is intentional for demos and validation. In future production mode, that automatic reset can be removed so blocks persist across restarts if desired.

## Google Cloud deployment notes

- Run the gateway on a Linux VM with `sudo` privileges.
- Ensure the monitored interface name in `gateway_main.py` matches the VM NIC.
- Ensure WireGuard is already up before starting the gateway.
- Allow the needed VPN and backend egress traffic in Google Cloud firewall rules.
- Keep the model files in `models/` and do not move the existing folder structure.
- Whenever the local backend tunnel changes, update `BACKEND_BASE_URL` in `.env` before restarting the gateway.

## Startup expectation

When the system starts cleanly it should:

1. disable selected NIC offload features
2. clear test-time firewall blocks from previous runs
3. begin monitoring packet rate
4. send periodic heartbeat updates to the backend
5. block the configured attacker IP when the threshold is crossed

## Notes

- If the backend is unavailable or out of plan limits, the gateway continues monitoring and blocking locally.
- The model and feature list are preserved because they are core parts of the system design.
- The current live runtime is primarily threshold-driven, with the model assets retained for the prediction component of the system.
