// ===================================== GENERATED ====================================

import "hash"
rule MISP_EVENT_5c4d619e_af25_4ddf_8d98_62e5ac99ee40_PART1 : generated
{
	meta:
		actor = "Mustang Panda (TA416)"
		attack_techniques = "T1001.003,T1003,T1003.001,T1003.002,T1003.003,T1003.004,T1003.006,T1005,T1007,T1010,T1012,T1014,T1016,T1018,T1021,T1021.001,T1021.002,T1021.003,T1021.004,T1021.006,T1027,T1027.001,T1027.002,T1027.005,T1027.011"
		MISP_EVENT_INFO = "KSA-TI Mustang Panda (TA416)"
		MISP_EVENT_UUID = "5c4d619e-af25-4ddf-8d98-62e5ac99ee40"
		MISP_ORIGIN = "Automatically generated from non-Yara attribute(s)"
	condition:
		hash.sha1(0, filesize) == "774a9c3ff01a3e734b7bec0c312120126295fad9"
		or hash.sha1(0, filesize) == "4c81777551a772218519fb6dd1a6672aade4a936"
		or hash.sha1(0, filesize) == "c72cc22ad328946201b069cddae0eee021d687b1"
		or hash.sha1(0, filesize) == "f14eaf5d648aebb2ed7b00b2cf4349263b30fb1c"
		or hash.sha1(0, filesize) == "603babf64a62989bf00e124955471519f0d8e8ed"
		or hash.sha1(0, filesize) == "fcb799d02e6c1b4ac76ec8c5e704c7c511762d2d"
		or hash.sha1(0, filesize) == "ed8ad981c73ed444f1b89c4bda71ed99ca966c5a"
		or hash.sha1(0, filesize) == "bd2533005a2eaed203054fd649fdbdcd3e3a860a"
		or hash.sha1(0, filesize) == "9136eed34bea473d0f8554fb1d914502b832f219"
		or hash.sha1(0, filesize) == "1a2f1c97a5883e8bb4edcdacfe176da98b266b42"
}
// =====================================   AS-IS  ====================================
