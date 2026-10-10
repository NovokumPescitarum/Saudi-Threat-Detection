# Saudi Threat Detection

Auto-generated detection content for threats targeting **Saudi Arabia** and the wider **Middle East**. Indicators are collected from open threat-intel sources, normalized, filtered for relevance and recency, uploaded to MISP, and exported here as YARA / IDS / SIEM rules.

**Last updated:** 2026-10-10 11:48 UTC  |  **Last ingest run:** 2026-10-10 11:46:35

## Strategy

Two complementary lenses are combined:

1. **Country-focused** — sources are queried for `saudi`/`ksa`/`gulf`/`mena`, `.sa` domains and Saudi-ransomware victims. These are tagged **Saudi**.
2. **APT-focused** — indicators are attributed to known threat actors using word-boundary alias matching, then grouped by actor. Saudi-targeting actors are tagged **Saudi**; broader regional actors are tagged **Middle East**.

**Recency:** only indicators observed within the last **90 days** are included (1,769 older relevant indicators were dropped). Undated indicators from curated feeds are retained.

## Summary

- **86,726** total indicators collected
- **886** recent **Saudi**-relevant indicators
- **994** recent **Middle East**-relevant indicators
- Detection rules: **19** YARA · **109** Suricata · **111** Snort · **1846** STIX2 indicators
- **19** MISP events  |  **81** Saudi ransomware victims

## IOCs by source

| Source | Indicators |
|---|---:|
| urlhaus | 32,857 |
| cins | 15,000 |
| eset_malware_ioc | 14,958 |
| threatfox | 6,493 |
| signature_base | 4,878 |
| tweetfeed | 3,990 |
| otx | 3,403 |
| malwarebazaar | 2,883 |
| circl_feed | 2,347 |
| malwarebazaar_tags | 385 |
| openphish | 300 |
| ransomware_live | 67 |
| dshield | 20 |
| feodo | 6 |
| urlscan | 2 |

## IOCs by type

| Type | Total | Saudi-relevant |
|---|---:|---:|
| url | 35,538 | 77 |
| ip | 18,381 | 22 |
| domain | 9,144 | 2 |
| sha256 | 8,576 | 694 |
| md5 | 7,818 | 317 |
| sha1 | 7,246 | 267 |
| email | 23 | 0 |

## Saudi-targeting actors

| Actor | Indicators |
|---|---:|
| POLONIUM (Plaid Rain) | 328 |
| MuddyWater (Seedworm / Static Kitten) | 183 |
| APT34 (OilRig / Helix Kitten) | 144 |
| FamousSparrow | 127 |
| XENOTIME (TRITON/TRISIS) | 26 |
| APT39 (Chafer) | 22 |
| Agrius (BlackShadow / Pink Sandstorm) | 21 |
| APT33 (Elfin / Peach Sandstorm) | 20 |
| Tortoiseshell (Imperial Kitten) | 4 |

## Middle East actors

| Actor | Indicators |
|---|---:|
| APT10 (menuPass) | 580 |
| APT27 (Emissary Panda / LuckyMouse) | 156 |
| BackdoorDiplomacy | 88 |
| APT37 (ScarCruft / InkySquid) | 71 |
| Arid Viper (APT-C-23 / Desert Falcon) | 45 |
| SparklingGoblin | 24 |
| Inception (Cloud Atlas) | 16 |
| Mustang Panda (TA416) | 10 |
| Patchwork (Dropping Elephant) | 4 |

## Top malware families

| Family | Indicators |
|---|---:|
| APT10 IOCs - Source: AlienVault OTX | 544 |
| polonium | 210 |
| muddywater | 183 |
| oilrig | 144 |
| famoussparrow | 96 |
| backdoordiplomacy | 66 |
| aridspy | 45 |
| scarcruft | 42 |
| C2 | 26 |
| sparklinggoblin | 24 |
| agrius | 21 |
| Emissary Panda Tools and Malware https://unit42.paloaltonetworks.com/emissary-panda-attacks-middle-east-government-sharepoint-servers/ | 20 |
| POLONIUM IOC - CreepySnail - https://www.welivesecurity.com/2022/10/11/polonium-targets-israel-creepy-malware/ | 20 |
| POLONIUM IOC - DeepCreep - https://www.welivesecurity.com/2022/10/11/polonium-targets-israel-creepy-malware/ | 17 |
| POLONIUM IOC - Small DLLs - https://www.welivesecurity.com/2022/10/11/polonium-targets-israel-creepy-malware/ | 11 |

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
| 3468 | KSA-TI APT37 (ScarCruft / InkySquid) | 71 |
| 3469 | KSA-TI APT39 (Chafer) | 22 |
| 3470 | KSA-TI Agrius (BlackShadow / Pink Sandstorm) | 21 |
| 3471 | KSA-TI Arid Viper (APT-C-23 / Desert Falcon) | 45 |
| 3472 | KSA-TI BackdoorDiplomacy | 66 |
| 3473 | KSA-TI MuddyWater (Seedworm / Static Kitten) | 183 |
| 3474 | KSA-TI POLONIUM (Plaid Rain) | 316 |
| 3475 | KSA-TI Tortoiseshell (Imperial Kitten) | 4 |
| 3476 | KSA-TI Unattributed | 11 |
| 3477 | KSA-TI XENOTIME (TRITON/TRISIS) | 26 |
| 3478 | KSA-TI APT10 (menuPass) | 580 |
| 3479 | KSA-TI Inception (Cloud Atlas) | 16 |
| 3480 | KSA-TI Mustang Panda (TA416) | 10 |
| 3481 | KSA-TI Patchwork (Dropping Elephant) | 4 |
| 3482 | KSA-TI FamousSparrow | 127 |
| 3483 | KSA-TI SparklingGoblin | 24 |

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

_Generated 2026-10-10 11:48 UTC._