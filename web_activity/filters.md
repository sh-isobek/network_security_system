# Dashboard/API filters

Recommended query parameters:
- `site`: exact or partial site/domain match
- `ip`: exact device IP
- `hostname`: endpoint hostname
- `device_id`: endpoint ID
- `username`: AD/endpoint username
- `from`: UTC start time
- `to`: UTC end time
- `action`: allowed/blocked
- `page`, `page_size`: pagination

For the admin dashboard, site filtering should return the matching devices,
timestamps, IPs, hostnames and users, with pagination. Avoid loading the entire
activity table into the browser.
