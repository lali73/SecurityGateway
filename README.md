# Security Gateway

This project is a lightweight traffic-protection gateway designed to run on a Google Cloud VM. It watches traffic on the VM network interface, detects high packet-rate attack behavior, blocks the configured attacker IP at the host firewall level, and reports health or attack events to an external backend dashboard.

The backend is currently running locally and exposed to the VM through a temporary Cloudflare tunnel URL. Because that URL changes after backend restarts, the gateway reads the backend base URL from `.env` so it can be updated in one place.

The gateway also now reads the protected-user identity fields from `.env`, so it can send the user mapping data the backend needs without editing Python code every time a protected profile changes.

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
  Sends heartbeat and attack notifications to the remote backend, using `BACKEND_BASE_URL` and the protected-user identity values from `.env`.
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

From the backend's perspective, this gateway is the enforcement service. The backend remains the source of truth for:

- which customer is subscribed
- which customer has protection enabled
- which VPN IP belongs to which customer
- which WireGuard key belongs to which customer
- which gateway peer reference belongs to which customer

This gateway does not own customer identity. It only sends the identifiers configured for the currently protected profile so the backend can resolve the correct user and attach alerts to that user's protection record.

Current gateway behavior:

- Base URL source: `.env` key `BACKEND_BASE_URL`
- Current local-backend tunnel URL: `https://ethics-hits-troubleshooting-sas.trycloudflare.com`
- Protected identity source: `.env` keys `PROTECTED_VPN_IP`, `WIREGUARD_PUBLIC_KEY`, and `GATEWAY_PEER_REF`
- Endpoint: `POST /api/alerts`
- Header: `X-Alert-Secret`
- JSON body during heartbeat:

```json
{
  "victim_vpn_ip": "10.0.0.12",
  "wireguard_public_key": "optional-client-public-key",
  "gateway_peer_ref": "optional-peer-reference",
  "gateway_id": "gateway-dev-1",
  "event_type": "heartbeat",
  "detected_at": "2026-04-08T12:00:00+00:00",
  "attacker_ip": "CLEAN"
}
```

- JSON body during attack:

```json
{
  "victim_vpn_ip": "10.0.0.12",
  "wireguard_public_key": "optional-client-public-key",
  "gateway_peer_ref": "optional-peer-reference",
  "gateway_id": "gateway-dev-1",
  "event_type": "attack_detected",
  "detected_at": "2026-04-08T12:00:05+00:00",
  "attacker_ip": "10.128.0.3"
}
```

The backend should:

- accept authenticated POST requests from the VM
- accept one or more of `victim_vpn_ip`, `wireguard_public_key`, and `gateway_peer_ref`
- return `200` or `201` on success
- record health and attack state for the dashboard
- verify that multiple identifiers point to the same protected user when more than one is present
- avoid returning large HTML error pages, because the gateway expects a machine-oriented API response

### Backend contract for this gateway

To integrate correctly with this gateway, the backend should implement the following rules.

#### 1. Protection profile is the lookup layer

The backend should maintain a protection mapping record for each protected customer that includes at least:

- `userId`
- `subscriptionStatus`
- `protectionEnabled`
- `vpnIp`
- `wireguardPublicKey`
- `gatewayPeerRef`
- `gatewayId`

When this gateway sends an alert, the backend should resolve the target customer from that protection mapping layer rather than from unrelated user data.

#### 2. At least one identifier must be accepted

This gateway may send any of the following identifiers:

- `victim_vpn_ip`
- `wireguard_public_key`
- `gateway_peer_ref`

The backend should be able to resolve the customer if at least one of them is present.

Recommended priority:

1. `victim_vpn_ip`
2. `wireguard_public_key`
3. `gateway_peer_ref`

#### 3. Multiple identifiers should be cross-checked

If the gateway sends more than one identity field, the backend should verify they all map to the same protection profile.

If they do not match, the backend should:

- reject the alert as an integration mismatch, or
- mark it as a conflict for investigation

The backend should not silently attach a conflicting alert to the wrong user.

#### 4. Heartbeats and attacks use the same identity

Both heartbeat events and attack events should be attached to the same protected customer record using the same identifiers.

That means the backend can show:

- this customer is currently protected
- this customer's gateway is healthy
- this customer was recently attacked

#### 5. Suggested response behavior

The backend should return:

- `200` or `201` when the alert is accepted
- `401` when the shared secret is wrong
- `404` when no protection profile matches the provided identity
- `409` when multiple identity fields conflict

Short JSON responses are preferred over HTML responses.

Example error:

```json
{
  "success": false,
  "message": "No protection profile found for the provided VPN IP"
}
```

#### 6. Recommended backend workflow

When a customer subscribes and is granted protection, the backend should:

1. create or update the customer record
2. allocate a VPN IP
3. create or register the WireGuard peer
4. store the WireGuard public key
5. store a stable `gateway_peer_ref` if used
6. mark the protection profile as enabled
7. issue the VPN config to the customer
8. ensure the gateway is configured with the same protected identity values for that profile

#### 7. Recommended ingestion logic

On `POST /api/alerts`, the backend should:

1. verify `X-Alert-Secret`
2. read the gateway identity fields
3. resolve the matching protection profile
4. confirm identity consistency if multiple identifiers are present
5. create the alert or heartbeat record
6. update the customer's latest protection status
7. push the event to the frontend/dashboard if applicable

#### 8. Current limitation of this repo

This repo currently sends alerts for one configured protected profile at a time.

That means the backend should understand:

- this gateway repo is not yet dynamically switching between many users by itself
- the configured identity in `.env` must match the customer currently being tested or protected in this repo state
- full multi-user dynamic mapping will require additional gateway-side logic later

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

## Updating the protected user identity

The backend resolves alerts to the correct customer using the protected identity values sent by this gateway. Those values are configured in `.env`.

Relevant keys:

```env
PROTECTED_VPN_IP=10.0.0.12
WIREGUARD_PUBLIC_KEY=
GATEWAY_PEER_REF=
GATEWAY_ID=gateway-dev-1
```

How to use them:

- `PROTECTED_VPN_IP`
  The VPN IP assigned to the protected customer. This is the most important field and should match the backend protection profile.
- `WIREGUARD_PUBLIC_KEY`
  Optional but recommended. Set this to the customer's WireGuard public key if the backend stores it.
- `GATEWAY_PEER_REF`
  Optional but recommended. Set this to the backend or gateway peer reference if your backend uses one.
- `GATEWAY_ID`
  Identifies which gateway instance sent the event.

Recommended practice:

1. always set `PROTECTED_VPN_IP`
2. set `WIREGUARD_PUBLIC_KEY` too when you know it
3. set `GATEWAY_PEER_REF` when your backend issues a stable peer reference
4. restart the gateway after changing any of these values

Backend team note:

- if the backend returns `"No user is assigned to the provided VPN IP"`, it means `PROTECTED_VPN_IP` in this gateway does not match the backend protection profile currently stored for that customer

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
- Whenever the protected user/profile changes, update the identity fields in `.env` before restarting the gateway.

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
- The current gateway can send richer user identity to the backend, but it still monitors one configured protected profile at a time in this repo state.
