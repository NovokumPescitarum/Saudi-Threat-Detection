// ===================================== GENERATED ====================================

import "hash"
rule MISP_EVENT_426d7196_ac60_446c_a69b_1d237f2a6290_PART1 : generated
{
	meta:
		actor = "Patchwork (Dropping Elephant)"
		attack_techniques = "T1003,T1003.001,T1005,T1010,T1012,T1016,T1020,T1021,T1021.001,T1027,T1027.001,T1027.002,T1027.005,T1027.010,T1033,T1036,T1036.005,T1039,T1047,T1053,T1053.005,T1055,T1055.001,T1055.012,T1056"
		MISP_EVENT_INFO = "KSA-TI Patchwork (Dropping Elephant)"
		MISP_EVENT_UUID = "426d7196-ac60-446c-a69b-1d237f2a6290"
		MISP_ORIGIN = "Automatically generated from non-Yara attribute(s)"
	condition:
		hash.md5(0, filesize) == "e42a8cef2e70d4f3c96c2b8073e7d396"
		or hash.md5(0, filesize) == "0fa12f215b8c5cfed492d3c5ee2867b3"
		or hash.md5(0, filesize) == "5c3456d5932544b779fe814133344fdb"
		or hash.md5(0, filesize) == "f396b476413558266f3abd336e06cbfc"
}
// =====================================   AS-IS  ====================================
