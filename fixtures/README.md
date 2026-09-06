# Fixtures

Offline clearance documents a server would publish at a well-known URI.
Tests never hit the network.

| File | Role |
| --- | --- |
| `trust_root.json` | Pinned host trust root (Ed25519 public key) |
| `clearance_valid.json` | Signed clearance for `weather.internal` → **admit** |
| `clearance_forged.json` | Same body, garbage signature → **deny** |
| `clearance_wrong_key.json` | Valid signature from a different key → **deny** |
| `clearance_expired.json` | Correctly signed, `not_after` in the past → **deny** |
| `clearance_wrong_server.json` | Signed for `evil.example` → **deny** |
| `clearance_not_yet_valid.json` | `not_before` in the future → **deny** |
| `clearance_confidential.json` | Sensitivity above host max → **deny** |
| `policy.json` | Expected server + max sensitivity |
| `allow_list.json` | `get_forecast` / `get_alerts` only |
| `dev_keys.json` | Sample keys so `scripts/sign_fixtures.py` is reproducible |

Regenerate (from repo root, after `PYTHONPATH=src`):

```bash
PYTHONPATH=src python scripts/sign_fixtures.py
```

`dev_keys.json` is a demo seed, not a production secret.
