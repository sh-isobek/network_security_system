# Upload implementation comparison — 2026-09-20

Repository heads and all five pull requests were checked directly on GitHub.
The nine published branch heads contain no alternate newer upload scanner.
The other open PR (#3) adds attendance/Face ID functionality and is unrelated.

Compared code:

- `main`: `76f36c8cae9f56e390686c9219817070b761a5eb` (agent 1.0.13).
- PR #5: `cff9d6103654ca091010dfb7d5b04f3aa886f516` (agent 1.0.14).

| Requirement | main | PR #5 |
| --- | --- | --- |
| Binary Android manifest parser | Present | Same parser retained |
| APK manifest decompression bound | Slices after full decompression | Bounded read before allocating full manifest |
| Upload unknown/suspicious samples | Hash and metadata only | Raw streamed upload, maximum 25 MiB |
| Verify uploaded content | No upload endpoint | Server recomputes SHA-256 |
| Authentication | Existing agent tokens | Same tokens, hostname binding on upload |
| Server analysis | Requires an existing stored sample | YARA, ClamAV and static analysis of uploaded sample |
| Sample deletion | No endpoint sample is received | Request directory removed before response/DB write |
| Scanner temporary output | Not applicable to endpoint uploads | ClamAV temporary output shares cleanup directory |
| Upload proxy copies | Default buffering | nginx request buffering disabled |
| Incomplete antivirus check | Not applicable to endpoint uploads | Explicit incomplete/unknown result |

## Selection

Keep PR #5: it builds on the current AXML implementation and adds the missing
upload/deletion lifecycle. Replacing main's parser with an older branch would
discard functionality without improving this requirement. No unrelated branch
or attendance feature is included.

This is a correctness and resource-bounds comparison, not a throughput
benchmark. Upload scans cost more network/CPU than hash lookup. Only server-
requested unknown/suspicious samples are sent; confirmed hash detections do
not trigger upload. Raw streaming avoids loading the whole upload into agent
memory and avoids multipart spooling.

## Verification and limits

- 18 lifecycle/API tests passed locally, including a real HTTP transfer and
  real YARA rule match; the existing AXML/APK regression test also passed.
- SQLite and PostgreSQL lifecycle CI passed on `cff9d61`:
  https://github.com/sh-isobek/network_security_system/actions/runs/35527903853
- The broader Linux integration run was still running at review time:
  https://github.com/sh-isobek/network_security_system/actions/runs/35527903834
- No production service was deployed or restarted during this review.
- Forced process termination can bypass cleanup. See `UPLOAD_SCAN.md` for
  temporary volume, swap/core dump, and deletion guarantees. This comparison
  does not claim forensic erasure or completed full-system verification.
