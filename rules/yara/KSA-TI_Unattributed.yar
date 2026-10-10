// ===================================== GENERATED ====================================


rule MISP_EVENT_e1133353_39e6_4820_837b_847875e2706d_PART1 : generated
{
	meta:
		MISP_EVENT_INFO = "KSA-TI Unattributed"
		MISP_EVENT_UUID = "e1133353-39e6-4820-837b-847875e2706d"
		MISP_ORIGIN = "Automatically generated from non-Yara attribute(s)"
	strings:
		$ = "soholat.sa" ascii wide
		$ = "https://soholat.sa/" ascii wide
	condition:
		any of them
}
// =====================================   AS-IS  ====================================
