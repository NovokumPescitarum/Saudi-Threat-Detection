// ===================================== GENERATED ====================================

import "hash"
rule MISP_EVENT_68d09893_c51c_4c15_b475_d542f1cb00bd_PART1 : generated
{
	meta:
		MISP_EVENT_INFO = "KSA-TI Tortoiseshell (Imperial Kitten)"
		MISP_EVENT_UUID = "68d09893-c51c-4c15-b475-d542f1cb00bd"
		MISP_ORIGIN = "Automatically generated from non-Yara attribute(s)"
	condition:
		hash.sha256(0, filesize) == "dfddbd09ccea598c4841f1abbc927f1c661d85d4bd9bcb081f7c811212d8a64a"
		or hash.sha256(0, filesize) == "612bdfb4f6eaf920a7a41fa06de8d99f6ecf6ad147374efa6eb1d5aff91df558"
		or hash.sha256(0, filesize) == "1534f95f49ddf2ada38561705f901e5938470c1678d6a81f0f4177ba7412ef5b"
		or hash.sha256(0, filesize) == "da65aa439e90d21b2cf53afef6491e7dcdca19dd1bbec50329d53f3d977ee089"
}
// =====================================   AS-IS  ====================================
