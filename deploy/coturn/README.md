# Self-hosted TURN relay

This configuration is a deployment starting point only. Replace the example realm, secret, public/private addresses, and TLS certificate paths before exposing the service. Keep UDP/TCP 3478, TLS 5349, and the configured relay UDP port range open in the host firewall.

The signaling service must issue time-limited TURN REST credentials using the same secret. Never place a long-lived static TURN username/password in the Windows client. Store the shared secret in the server's secret store, rotate it during planned maintenance, and limit allocations and bandwidth to the expected two devices.

Start with `docker compose up -d`; inspect logs with `docker compose logs -f coturn`; stop with `docker compose down`. Pin and review image updates before updating the version. This service forwards WebRTC-encrypted packets and does not terminate the peer DTLS connection.

The configuration has not yet been verified against a live external coturn host or NAT/firewall. Do not treat the placeholder secrets/hostnames as production-ready values.
