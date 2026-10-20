# Saudi Threat Detection

Auto-generated research and detection content with heuristic **Saudi Arabia** and **Middle East** relevance. Regional labels are associations, not confirmed targeting. Indicators are collected from open sources, normalized, filtered using legacy relevance/date rules, and exported from MISP as YARA / IDS / SIEM content.

**Last updated:** 2026-10-20 10:41 UTC  |  **Last ingest run:** 2026-10-20T01:20:00.983483+00:00

## Validation scope

Compilation and parsing do not prove detection accuracy, source maliciousness, current activity or confirmed Saudi targeting. Current content is not independently source-verified. Positive/negative behavior testing applies only to the exact artifact revisions and cases listed in separate test receipts, not automatically to every rule.

The publication path requires native YARA, Sigma and Suricata checks. Snort uses an explicitly disclosed structural-only continuity policy when its native engine is unavailable; STIX checks are structural rather than full pattern/schema certification. These limitations are not native or real-world detection passes.

Local DB statistics use a read-only SQLite snapshot. Recency flags are stored classifications, not a fresh activity assessment; report-only does not run validation or contact remote services. Rule counts are local inventory, and ATT&CK mappings are associations, not tested coverage.

### Candidate publication gates and quality modes

The legacy pipeline stages rule exports and Sigma selection in a private candidate, requires successful export, ATT&CK, Sigma and native/structural QA stages, then atomically promotes the candidate while retaining the previous generation. GitHub publication rechecks QA, allowlisted content and configured-secret leakage; dirty generated checkout paths block publication, and a push is successful only after remote-head verification.

Native checks cover YARA compilation with limited benign probes, Sigma syntax (not SIEM runtime), and Suricata configuration/rule loading (not packet behavior). Reviewed no-applicable-rule responses remain explicitly empty, not native passes. Separate controlled positive/benign receipts apply only to their exact hashes and selected cases.

Legacy mode uses stored relevance/date selections and MISP-derived content; it does not certify source evidence. Opt-in `quality_enabled: true` or `--local-quality-only` uses the strict `v_detection_ready` lane with private audits and holds legacy MISP/GitHub publication. This README does not activate that lane or certify its deployment.

Safe local regeneration: `python3 pipeline.py --report-only --db data/iocs.db`. It writes only the local README; MISP metadata remains unknown. Legacy `--dry-run` still collects and queries MISP; `--no-misp` skips pushes, not remote reads.

### Complete-pack private-lab validation

The private detection lab uses the complete authoritative rule pack, including explicit unsupported/sample/fixture gaps, rather than treating a selected subset as full coverage. `python3 pipeline.py --lab-handoff-only` emits a local full-pack hash inventory and historical binding comparison; it does not load the lab, validate rules or publish. Sealed lab inputs require reviewed re-freezing/rebinding before changed rules are loaded.

Lab evidence must distinguish query-only, persisted-alert-tested, native-compile-only and behavior-tested results, and retain sample/fixture gaps. Historical success is not fresh validation. New public uploads require exact current hashes bound to reviewed validation receipts; unsupported/failed inputs must not be represented as validated. Private receipts and telemetry are excluded.

<!-- public-validation-summary:start -->

### Recorded hash-bound lab evidence

This README refresh does not execute a lab run or upload.

Recorded completion: **2026-10-20T10:41:58Z** (not a new run).

Raw bound inventory: **2429 files**; files are not unique rules or validated cases.

Reviewed private receipt SHA-256: `c31ad732bfe92c2a855b282673c19088097c3d0c54b25e0914270bfb8cfeddef`.

| Evidence category | Files | Passed cases | Failed cases |
|---|---:|---:|---:|
| behavior-tested | 5 | 1048 | 0 |
| persisted-alert-tested | 10 | 30 | 0 |
| query-only | 1991 | 5973 | 0 |
| native-compile-only | 30 | 30 | 0 |
| structural-only | 0 | 0 | 0 |
| unsupported | 0 | 0 | 0 |
| not-tested | 393 | 0 | 0 |
| failed | 0 | 0 | 0 |

Gaps (file counts): sample-unavailable: 25; fixture-unavailable: 347; engine-unavailable: 0; unsupported-feature: 0; telemetry-unavailable: 0; not-executed: 51; check-failed: 0.

Cases are recorded per artifact, not deduplicated scenarios. Query, compile and structural checks are not behavior validation. Gapped/unsupported/failed inputs remain held; this summary is not blanket upload approval or real-world accuracy evidence.

#### Original versus normalized publication

Canonical originals are preserved. Only first-msg descriptive quote escaping differs in the files below; headers and detection-option bytes are unchanged. Both exact-byte lanes compiled in native Snort; normalized Snort runtime positive/negative cases are **not tested**. Unchanged files retain their original exact-byte evidence and gaps.

Original full-pack receipt SHA-256: `537561dc4c527bf06b36ec85f6125b2f24454ab2c89879019cdc24601858c7b0`.

Separate native original/normalized compile receipt SHA-256: `e4507386d01f3358de0a1e21e1d853cb489a613a0190c79398bea35b72f47785`.

Independent mapping/implementation review SHA-256: `53089c5c405d2b2cb1a0c8156f59f43f62bb4ec3bd7db5af9e4b58e42538b650`.

##### `ids/snort/KSA-TI_APT10_menuPass.rules`

- Original SHA-256: `cdb79ea1f2326ec8a1e53bf4968597655375d692d6a2595715a22e091aea4f2b`
- Published normalized SHA-256: `a1f1860b153da385a20e7eadac4fb09dd8e637fdab9673be50d83b54f5ca6064`

##### `ids/snort/all_ksa.rules`

- Original SHA-256: `6d960a5832ec5056c7c3e851ef79514a103f3552468c0f5fb6ea433ce41170dd`
- Published normalized SHA-256: `31e53c774e363cc01ad3e1840a6f910c86546802f0b5186d69f345523bc1e894`

<!-- public-validation-summary:end -->

## Strategy

Two complementary lenses are combined:

1. **Country-focused** — sources are queried for `saudi`/`ksa`/`gulf`/`mena`, `.sa` domains and Saudi-ransomware victims. These are tagged **Saudi**.
2. **Actor association** — known actor aliases in metadata are matched and grouped. A regional actor association does not independently establish attribution or the victim country for each indicator.

**Legacy recency selection:** source-provided dates within **90 days** are used; these are not necessarily verified attack-observation dates. 3,689 older or undated relevant records are excluded from the current selection. Previously stored MISP attributes may remain in derived exports.

## Summary

- **127,345** total indicators collected
- **85** recent **Saudi**-relevant indicators
- **58** recent **Middle East**-relevant indicators
- Detection rules: **24** YARA · **262** Suricata · **265** Snort · **2343** Sigma · **387** STIX2 indicators
- **unknown (not queried)** MISP events  |  **83** Saudi ransomware victims
- ATT&CK associations: **482** techniques across **33** tracked Saudi/MEA actors (not tested coverage)

## IOCs by source

| Source | Indicators |
|---|---:|
| urlhaus | 37,856 |
| threatfox | 21,642 |
| eset_malware_ioc | 19,428 |
| malwarebazaar | 17,304 |
| cins | 15,000 |
| tweetfeed | 5,173 |
| signature_base | 4,878 |
| otx | 3,412 |
| openphish | 3,300 |
| circl_feed | 2,347 |
| malwarebazaar_tags | 385 |
| research:2026-10-10 | 99 |
| ransomware_live | 69 |
| research:https://securelist.com/mirage-kitten-new-tools/120811/ | 32 |
| research:https://www.group-ib.com/blog/heavygram-handala-hack-telegram-c2/ | 22 |
| dshield | 20 |
| research:https://www.welivesecurity.com/en/eset-research/beware-sparrowock-backdoor-bites-commands-catch/ | 19 |
| research:https://www.group-ib.com/blog/remcontrol-android-banking-trojan/ | 18 |
| research:https://securelist.com/mirage-kitten-new-backdoors-noderabbit-pollcat/121244/ | 11 |
| research:https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/ | 8 |
| feodo | 6 |
| research:https://www.group-ib.com/blog/tortoiseshell-apt-toolset-infrastructure/ | 2 |
| urlscan | 2 |

## IOCs by type

| Type | Total | Saudi-relevant |
|---|---:|---:|
| url | 49,615 | 83 |
| ip | 20,253 | 52 |
| sha256 | 16,571 | 696 |
| md5 | 14,154 | 330 |
| sha1 | 13,550 | 269 |
| domain | 13,179 | 44 |
| email | 23 | 0 |

## Actor associations in Saudi-relevant records

| Actor | Indicators |
|---|---:|
| Tortoiseshell | 77 |
| Tortoiseshell (Imperial Kitten) | 4 |

## Middle East actors

| Actor | Indicators |
|---|---:|
| Mirage Kitten | 12 |
| Tortoiseshell (Imperial Kitten) | 2 |

## Top malware families

| Family | Indicators |
|---|---:|
| NodeRabbit/PollCat | 48 |
| RemControl | 18 |
| HEAVYGRAM | 8 |
| Blinder Tunnel | 6 |
| TWOSTROKE | 3 |
| ClearFake | 1 |
| Unknown malware | 1 |

## Ransomware victims (Saudi Arabia)

_83 victim listings tracked from public ransomware leak sites (via ransomware.live)._

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

_unknown (not queried); offline report has no live MISP metadata._

## Content

```
rules/
├── yara/            # YARA rules (all_ksa.yar + per-actor)
├── ids/suricata/    # Suricata NIDS rules (all_ksa.rules + per-actor)
├── ids/snort/       # Snort NIDS rules
├── sigma/           # behavioural Sigma rules (ATT&CK-mapped to our actors)
└── siem/stix2/      # STIX2 bundles
```

## Sources

AlienVault OTX · abuse.ch (ThreatFox, MalwareBazaar, URLhaus, Feodo Tracker) · OpenPhish · Neo23x0 signature-base · ESET malware-ioc · TweetFeed · ransomware.live. New sources are added by dropping a collector module into the pipeline.

## Disclaimer

Auto-generated for defensive detection engineering. Indicators are unverified open-source intelligence and may produce false positives — validate before enforcement. MISP-generated YARA may contain exact-hash and string-pattern conditions; technical test success does not establish malware-family coverage.

_Generated 2026-10-20 10:41 UTC._