# Web activity integration

## Data source
Use a source that actually records web requests (for example a proxy/web gateway,
firewall URL logging, or endpoint browser telemetry). The endpoint agent alone
cannot reliably know every website visited.

## Correlation
1. Receive web event with timestamp + source IP.
2. Resolve the device from DHCP/network inventory at that timestamp.
3. Correlate hostname/device ID/user where available.
4. Store normalized event in `web_activity`.
5. Expose paginated API filters for `site`, `ip`, `hostname`, device and time.
6. Dashboard displays matching devices and timestamps.

## Important limitation
DNS logs can provide domain lookup activity, but they do not prove that a page
was successfully visited. For exact website access history, use HTTP(S) proxy,
firewall URL logs, or endpoint telemetry with appropriate organizational policy.
