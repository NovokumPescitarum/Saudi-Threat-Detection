# Saudi Threat Detection

Auto-generated detection content for threats targeting **Saudi Arabia / the Gulf**.
Indicators are collected from open threat-intel sources, normalized, tagged for
Saudi relevance, uploaded to MISP, and exported here as YARA / IDS / SIEM rules.

**Last updated:** 2026-10-10 09:34 UTC  |  **Last ingest run:** 2026-10-10 09:19:57

## Summary

- **49,594** total indicators collected
- **1,908** tagged Saudi/Gulf-relevant
- Detection rules: **9** YARA · **1647** Suricata · **1665** Snort · **3778** STIX2 indicators
- **8** MISP events

## IOCs by source

| Source | Indicators |
|---|---:|
| urlhaus | 32,810 |
| otx | 7,592 |
| threatfox | 6,468 |
| malwarebazaar | 2,901 |
| openphish | 300 |
| feodo | 6 |

## IOCs by type

| Type | Total | Saudi-relevant |
|---|---:|---:|
| url | 34,529 | 101 |
| domain | 7,594 | 521 |
| ip | 2,441 | 1 |
| sha256 | 1,885 | 217 |
| md5 | 1,650 | 612 |
| sha1 | 1,470 | 437 |
| email | 25 | 19 |

## Saudi-relevant IOCs by attributed actor

| Actor | Indicators |
|---|---:|
| Gaza Cybergang | 168 |
| APT34/OilRig | 156 |
| MuddyWater | 76 |
| APT33/Elfin | 53 |
| APT42/Magic Hound | 49 |
| GreenBug | 35 |
| Molerats | 22 |

## MISP events

| Event | Info | Attributes |
|---:|---|---:|
| 3454 | KSA-TI APT33/Elfin | 53 |
| 3455 | KSA-TI APT34/OilRig | 156 |
| 3456 | KSA-TI APT42/Magic Hound | 49 |
| 3457 | KSA-TI Gaza Cybergang | 168 |
| 3458 | KSA-TI GreenBug | 35 |
| 3459 | KSA-TI Molerats | 22 |
| 3460 | KSA-TI MuddyWater | 76 |
| 3461 | KSA-TI Unattributed | 1349 |

## Content

```
rules/
├── yara/            # YARA rules (all_ksa.yar + per-event)
├── ids/suricata/    # Suricata NIDS rules (all_ksa.rules + per-event)
├── ids/snort/       # Snort NIDS rules
└── siem/stix2/      # STIX2 bundles
```

## Sources

AlienVault OTX · abuse.ch (ThreatFox, MalwareBazaar, URLhaus, Feodo Tracker) · OpenPhish.
New sources are added by dropping a collector module into the pipeline.

## Disclaimer

Auto-generated for defensive detection engineering. Indicators are unverified
open-source intelligence and may produce false positives — validate before
enforcement. MISP-generated YARA is string-based and intentionally broad.

_Generated 2026-10-10 09:34 UTC._