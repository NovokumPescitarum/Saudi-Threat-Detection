// ===================================== GENERATED ====================================

import "hash"
rule MISP_EVENT_bea11215_8c9b_4abe_a190_82f2ccc98b7b_PART1 : generated
{
	meta:
		MISP_EVENT_INFO = "KSA-TI Research 7669d3486c54769a"
		MISP_EVENT_UUID = "bea11215-8c9b-4abe-a190-82f2ccc98b7b"
		MISP_ORIGIN = "Automatically generated from non-Yara attribute(s)"
	condition:
		hash.sha256(0, filesize) == "6e7d9b33f1e72ea1ede71373a604ecdb060dab7d42055179c1eede9ecd1fd239"
		or hash.sha256(0, filesize) == "f5b12772db6817f7a765a6fe7565fd3d4f87edc28e42fe3ec0244a372a410fc9"
		or hash.sha256(0, filesize) == "53f35e49eb9b271fd8cbcd3daacb525328dbf159a03dbd1c7adebe0363daa402"
		or hash.sha256(0, filesize) == "3fd810a3aa0039993393741b32287c367a9a5037a41e826906440887cdd3ed13"
		or hash.sha256(0, filesize) == "76273382e4252c1f60a2251141e108942494409c759358320735891762c0682e"
		or hash.sha256(0, filesize) == "d3561bd4aad003dc3e08157b0891860bb496b80cd6e44901692e08ab1d4e8260"
		or hash.sha256(0, filesize) == "f5ba1645694c62f527ed6ceda8c68a5c3dd92b4032439167e8e937e72803b4bd"
		or hash.sha256(0, filesize) == "7cc571aca6d8715d9aaad3d83e1bcd30467565d583db1dfe73697c5d00a1f875"
}
// =====================================   AS-IS  ====================================
