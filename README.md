# Saudi Threat Detection

Auto-generated detection content for threats targeting **Saudi Arabia** and the wider **Middle East**. Indicators are collected from open threat-intel sources, normalized, filtered for relevance and recency, uploaded to MISP, and exported here as YARA / IDS / SIEM rules.

**Last updated:** 2026-10-10 10:27 UTC  |  **Last ingest run:** 2026-10-10 10:22:49

## Strategy

Two complementary lenses are combined:

1. **Country-focused** — sources are queried for `saudi`/`ksa`/`gulf`/`mena`, `.sa` domains and Saudi-ransomware victims. These are tagged **Saudi**.
2. **APT-focused** — indicators are attributed to known threat actors using word-boundary alias matching, then grouped by actor. Saudi-targeting actors are tagged **Saudi**; broader regional actors are tagged **Middle East**.

**Recency:** only indicators observed within the last **90 days** are included (0 older relevant indicators were dropped). Undated indicators from curated feeds are retained.

## Summary

- **50,043** total indicators collected
- **540** recent **Saudi**-relevant indicators
- **252** recent **Middle East**-relevant indicators
- Detection rules: **13** YARA · **3** Suricata · **4** Snort · **780** STIX2 indicators
- **13** MISP events  |  **81** Saudi ransomware victims

## IOCs by source

| Source | Indicators |
|---|---:|
| urlhaus | 32,846 |
| threatfox | 6,482 |
| signature_base | 4,878 |
| malwarebazaar | 2,853 |
| otx | 2,743 |
| eset_malware_ioc | 399 |
| openphish | 300 |
| tweetfeed | 20 |
| feodo | 6 |

## IOCs by type

| Type | Total | Saudi-relevant |
|---|---:|---:|
| url | 33,652 | 1 |
| domain | 6,801 | 1 |
| ip | 2,765 | 0 |
| sha256 | 2,606 | 188 |
| md5 | 2,140 | 116 |
| sha1 | 2,079 | 234 |

## Saudi-targeting actors

| Actor | Indicators |
|---|---:|
| MuddyWater (Seedworm / Static Kitten) | 183 |
| APT34 (OilRig / Helix Kitten) | 144 |
| POLONIUM (Plaid Rain) | 118 |
| XENOTIME (TRITON/TRISIS) | 26 |
| APT39 (Chafer) | 22 |
| Agrius (BlackShadow / Pink Sandstorm) | 21 |
| APT33 (Elfin / Peach Sandstorm) | 20 |
| Tortoiseshell (Imperial Kitten) | 4 |

## Middle East actors

| Actor | Indicators |
|---|---:|
| APT27 (Emissary Panda / LuckyMouse) | 156 |
| Arid Viper (APT-C-23 / Desert Falcon) | 45 |
| APT37 (ScarCruft / InkySquid) | 29 |
| BackdoorDiplomacy | 22 |

## Top malware families

| Family | Indicators |
|---|---:|
| muddywater | 183 |
| oilrig | 144 |
| aridspy | 45 |
| agrius | 21 |
| Emissary Panda Tools and Malware https://unit42.paloaltonetworks.com/emissary-panda-attacks-middle-east-government-sharepoint-servers/ | 20 |
| POLONIUM IOC - CreepySnail - https://www.welivesecurity.com/2022/10/11/polonium-targets-israel-creepy-malware/ | 20 |
| POLONIUM IOC - DeepCreep - https://www.welivesecurity.com/2022/10/11/polonium-targets-israel-creepy-malware/ | 17 |
| POLONIUM IOC - Small DLLs - https://www.welivesecurity.com/2022/10/11/polonium-targets-israel-creepy-malware/ | 11 |
| POLONIUM IOC - CreepyDrive - https://www.welivesecurity.com/2022/10/11/polonium-targets-israel-creepy-malware/ | 8 |
| POLONIUM IOC - MegaCreep - https://www.welivesecurity.com/2022/10/11/polonium-targets-israel-creepy-malware/ | 8 |
| POLONIUM IOC - FlipCreep - https://www.welivesecurity.com/2022/10/11/polonium-targets-israel-creepy-malware/ | 7 |
| POLONIUM IOC - Keylogger modules - https://www.welivesecurity.com/2022/10/11/polonium-targets-israel-creepy-malware/ | 7 |
| POLONIUM IOC - PapaCreep - https://www.welivesecurity.com/2022/10/11/polonium-targets-israel-creepy-malware/ | 7 |
| ScarCruft malware - Installer - https://securelist.com/scarcruft-continues-to-evolve-introduces-bluetooth-harvester/90729/ | 6 |
| Bronze Union IOC - MD5 hash - SysUpdate installer (self-extracting RAR file) associated with BRONZE UNION | 5 |

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

## MISP events

| Event | Info | Attributes |
|---:|---|---:|
| 3465 | KSA-TI APT27 (Emissary Panda / LuckyMouse) | 156 |
| 3466 | KSA-TI APT33 (Elfin / Peach Sandstorm) | 20 |
| 3467 | KSA-TI APT34 (OilRig / Helix Kitten) | 144 |
| 3468 | KSA-TI APT37 (ScarCruft / InkySquid) | 29 |
| 3469 | KSA-TI APT39 (Chafer) | 22 |
| 3470 | KSA-TI Agrius (BlackShadow / Pink Sandstorm) | 21 |
| 3471 | KSA-TI Arid Viper (APT-C-23 / Desert Falcon) | 45 |
| 3472 | KSA-TI BackdoorDiplomacy | 22 |
| 3473 | KSA-TI MuddyWater (Seedworm / Static Kitten) | 183 |
| 3474 | KSA-TI POLONIUM (Plaid Rain) | 106 |
| 3475 | KSA-TI Tortoiseshell (Imperial Kitten) | 4 |
| 3476 | KSA-TI Unattributed | 2 |
| 3477 | KSA-TI XENOTIME (TRITON/TRISIS) | 26 |

## Content

```
rules/
├── yara/            # YARA rules (all_ksa.yar + per-actor)
├── ids/suricata/    # Suricata NIDS rules (all_ksa.rules + per-actor)
├── ids/snort/       # Snort NIDS rules
└── siem/stix2/      # STIX2 bundles
```

## Sources

AlienVault OTX · abuse.ch (ThreatFox, MalwareBazaar, URLhaus, Feodo Tracker) · OpenPhish · Neo23x0 signature-base · ESET malware-ioc · TweetFeed · ransomware.live. New sources are added by dropping a collector module into the pipeline.

## Disclaimer

Auto-generated for defensive detection engineering. Indicators are unverified open-source intelligence and may produce false positives — validate before enforcement. MISP-generated YARA is string-based and intentionally broad.

_Generated 2026-10-10 10:27 UTC._