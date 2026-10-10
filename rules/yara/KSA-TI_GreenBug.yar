// ===================================== GENERATED ====================================

import "hash"
rule MISP_EVENT_fb364029_7a99_48f8_a483_1e3132774441_PART1 : generated
{
	meta:
		MISP_EVENT_INFO = "KSA-TI GreenBug"
		MISP_EVENT_UUID = "fb364029-7a99-48f8-a483-1e3132774441"
		MISP_ORIGIN = "Automatically generated from non-Yara attribute(s)"
	strings:
		$ = "winappupdater.com" ascii wide
		$ = "syncwin.com" ascii wide
		$ = "update.winappupdater.com" ascii wide
		$ = "arielsecurityupdater.com" ascii wide
	condition:
		hash.md5(0, filesize) == "03e0260259ad931b5885fccac1dafe3b"
		or hash.md5(0, filesize) == "b5257339812af1dbb8b6a83a93137282"
		or hash.md5(0, filesize) == "bf4b07c7b4a4504c4192bd68476d63b5"
		or hash.md5(0, filesize) == "fa3dbe37108b752c38bf5870b5862ce5"
		or hash.md5(0, filesize) == "41b450a94784fa53790ebfdcacad7daf"
		or hash.md5(0, filesize) == "a96d211795852b6b14e61327bbcc3473"
		or hash.md5(0, filesize) == "146a112cb01cd4b8e06d36304f6bdf7b"
		or hash.md5(0, filesize) == "ad4229879180e267f431ac6666b6a0a2"
		or hash.sha1(0, filesize) == "62caa9cb00bf0b8e97ec6d1383368a0c8e9b42d7"
		or hash.sha1(0, filesize) == "d843a65ad0e3c2f2fd87c30c6cb0f6b66d6355d1"
		or hash.sha1(0, filesize) == "f5ee16fc76a7807cd13101de8cdbce0724789b6d"
		or hash.sha1(0, filesize) == "2e106e67876b52c4545763fe6741ad8e9eeb2b09"
		or hash.sha1(0, filesize) == "4c85c5062ece9aec26b6bf6a785ec7e60c824b0b"
		or hash.sha1(0, filesize) == "d92b0710474ade5097f28425884ad65b6bb5939d"
		or hash.sha1(0, filesize) == "0e47a027651133ab980dd040d3347d2028ffd32d"
		or hash.sha1(0, filesize) == "c191c35ac423b381efc84edce74d7a96dbd9ac7d"
		or hash.sha256(0, filesize) == "4744df6ac02ff0a3f9ad0bf47b15854bbebb73c936dd02f7c79293a2828406f6"
		or hash.sha256(0, filesize) == "394a7ebad5dfc13d6c75945a61063470dc3b68f7a207613b79ef000e1990909b"
		or hash.sha256(0, filesize) == "c7fc1f9c2bed748b50a599ee2fa609eb7c9ddaeb9cd16633ba0d10cf66891d8a"
		or hash.sha256(0, filesize) == "61c1c8fc8b268127751ac565ed4abd6bdab8d2d0f2ff6074291b2d54b0228842"
		or hash.sha256(0, filesize) == "128fa5815c6fee68463b18051c1a1ccdf28c599ce321691686b1efa4838a2acd"
		or hash.sha256(0, filesize) == "5a826b4fa10891cf63aae832fc645ce680a483b915c608ca26cedbb173b1b80a"
		or hash.sha256(0, filesize) == "47bb36cd2832a18b5ae951cf5a7d44fba6d8f5dca0a372392d40f51d1fe1ac34"
		or hash.sha256(0, filesize) == "7f16824e7ad9ee1ad2debca2a22413cde08f02ee9f0d08d64eb4cb318538be9c"
		or hash.sha256(0, filesize) == "308a646f57c8be78e6a63ffea551a84b0ae877b23f28a660920c9ba82d57748f"
		or hash.sha256(0, filesize) == "319a001d09ee9d754e8789116bbb21a3c624c999dae9cf83fde90a3fbe67ee6c"
		or hash.sha256(0, filesize) == "21f5e60e9df6642dbbceca623ad59ad1778ea506b7932d75ea8db02230ce3685"
		or hash.sha256(0, filesize) == "44bdf5266b45185b6824898664fd0c0f2039cdcb48b390f150e71345cd867c49"
		or hash.sha256(0, filesize) == "6b28a43eda5b6f828a65574e3f08a6d00e0acf84cbb94aac5cec5cd448a4649d"
		or hash.sha256(0, filesize) == "82beaef407f15f3c5b2013cb25901c9fab27b086cadd35149794a25dce8abcb9"
		or hash.sha256(0, filesize) == "dab460a0b73e79299fbff2fa301420c1d97a36da7426acc0e903c70495db2b76"
		or any of them
}
// =====================================   AS-IS  ====================================
