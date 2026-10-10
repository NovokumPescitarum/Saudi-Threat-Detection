# Saudi Threat Detection

Auto-generated detection content for threats targeting **Saudi Arabia / the Gulf**.
Indicators are collected from open threat-intel sources, normalized, tagged for
Saudi relevance, uploaded to MISP, and exported here as YARA / IDS / SIEM rules.

**Last updated:** 2026-10-10 10:09 UTC  |  **Last ingest run:** 2026-10-10 09:53:39

## Summary

- **60,133** total indicators collected
- **5,137** tagged Saudi/Gulf-relevant
- Detection rules: **13** YARA · **4405** Suricata · **4630** Snort · **5102** STIX2 indicators
- **11** MISP events
- **81** Saudi ransomware victims tracked (leak-site intel)

## IOCs by source

| Source | Indicators |
|---|---:|
| urlhaus | 32,830 |
| otx | 12,754 |
| threatfox | 6,508 |
| signature_base | 4,878 |
| malwarebazaar | 2,901 |
| eset_malware_ioc | 399 |
| openphish | 300 |
| ransomware_live | 67 |
| tweetfeed | 20 |
| feodo | 6 |

## IOCs by type

| Type | Total | Saudi-relevant |
|---|---:|---:|
| url | 36,034 | 1,532 |
| domain | 11,680 | 1,029 |
| sha256 | 3,633 | 778 |
| md5 | 3,175 | 1,043 |
| ip | 2,773 | 4 |
| sha1 | 2,763 | 705 |
| email | 75 | 46 |

## Saudi-relevant IOCs by attributed actor

| Actor | Indicators |
|---|---:|
| MuddyWater | 1,361 |
| APT34/OilRig | 732 |
| APT35/Charming Kitten | 522 |
| APT33/Elfin | 266 |
| Gaza Cybergang | 168 |
| Agrius/BlackShadow | 142 |
| APT42/Magic Hound | 137 |
| GreenBug | 60 |
| Molerats | 22 |
| APT39/Chafer | 22 |

## Top malware families (Saudi-relevant)

| Family | Indicators |
|---|---:|
| muddywater | 183 |
| oilrig | 144 |
| agrius | 21 |
| ransomhub | 7 |
| incransom | 7 |
| Greenbug IOC Webshell | 7 |
| Greenbug IOC Unknown | 7 |
| Elfin Report on APT33 - Remcos | 5 |
| lockbit3 | 4 |
| dragonransomware | 4 |
| alphv | 4 |
| nova | 3 |
| killsec | 3 |
| dragonforce | 3 |
| clop | 3 |

## MISP events

| Event | Info | Attributes |
|---:|---|---:|
| 3454 | KSA-TI APT33/Elfin | 266 |
| 3455 | KSA-TI APT34/OilRig | 732 |
| 3456 | KSA-TI APT42/Magic Hound | 137 |
| 3457 | KSA-TI Gaza Cybergang | 168 |
| 3458 | KSA-TI GreenBug | 60 |
| 3459 | KSA-TI Molerats | 22 |
| 3460 | KSA-TI MuddyWater | 1361 |
| 3461 | KSA-TI Unattributed | 1716 |
| 3462 | KSA-TI APT35/Charming Kitten | 522 |
| 3463 | KSA-TI APT39/Chafer | 22 |
| 3464 | KSA-TI Agrius/BlackShadow | 142 |

## Ransomware victims (Saudi Arabia)

_81 victim listings tracked from public ransomware leak sites (via ransomware.live)._
| Ransomware group | Victim listings |
|---|---:|
| ransomhub | 7 |
| incransom | 7 |
| lockbit3 | 5 |
| thegentlemen | 4 |
| dragonransomware | 4 |
| alphv | 4 |
| qilin | 3 |
| nova | 3 |
| killsec | 3 |
| dragonforce | 3 |
| clop | 3 |
| ransomhouse | 2 |
| ransomexx | 2 |
| ralord | 2 |
| krybit | 2 |

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

_Generated 2026-10-10 10:09 UTC._