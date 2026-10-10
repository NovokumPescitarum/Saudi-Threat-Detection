// ===================================== GENERATED ====================================

import "hash"
rule MISP_EVENT_86962c95_0fd2_48d2_8d04_ed9e36a79c94_PART1 : generated
{
	meta:
		MISP_EVENT_INFO = "KSA-TI SparklingGoblin"
		MISP_EVENT_UUID = "86962c95-0fd2-48d2-8d04-ed9e36a79c94"
		MISP_ORIGIN = "Automatically generated from non-Yara attribute(s)"
	condition:
		hash.md5(0, filesize) == "cde90ac52c964a6c6b4326347822c561"
		or hash.md5(0, filesize) == "a1d972a6aa398d0230e577227b28e499"
		or hash.md5(0, filesize) == "1d36404f85d94bea6c976044cb342f24"
		or hash.md5(0, filesize) == "245fa4cc813d368129e3bb00d52c570a"
		or hash.md5(0, filesize) == "6fb64677980d2cae622e9ed6e4f4c449"
		or hash.md5(0, filesize) == "c629ae2af8689989fc14b26405761d03"
		or hash.md5(0, filesize) == "8309ef02bec30b1e69815b5134ee1f43"
		or hash.md5(0, filesize) == "470a092abd67e25463425b611088b1db"
		or hash.sha1(0, filesize) == "1077a3dc0d9ccfbb73bd9f2e6b72bc67addcf2ab"
		or hash.sha1(0, filesize) == "153b8e46458bd65a68a89d258997e314fef72181"
		or hash.sha1(0, filesize) == "829aadbde42df14ce8ed06ac02ad697a6c9798fe"
		or hash.sha1(0, filesize) == "9762bc1c4cb04fe8eaeef50a4378a8d188d85360"
		or hash.sha1(0, filesize) == "ea44e9fbdbe5906a7fc469a988d83587e8e4b20d"
		or hash.sha1(0, filesize) == "aa5b5f24bdfb049ef51bbb6246cb56cec89752bf"
		or hash.sha1(0, filesize) == "fa6a40d3fc5cd4d975a01e298179a0b36aa02d4e"
		or hash.sha1(0, filesize) == "7df0be2774b17f672b96860d013a933e97862e6c"
		or hash.sha256(0, filesize) == "34f95e0307959a376df28bc648190f72bccc5b25e0e00e45777730d26abb5316"
		or hash.sha256(0, filesize) == "d52de1c29be8668a69af6c98ad86ec46eb94a3b0329e03d9fb44bb703070a771"
		or hash.sha256(0, filesize) == "9cf4e03defd1e58ff5767c230281c7d72a46bc350e99162281358ad771d1865f"
		or hash.sha256(0, filesize) == "6c2fd9badb7a323c5a4fd490e401a30064dbde275154ac81baa31d99ae6ca1ab"
		or hash.sha256(0, filesize) == "ce16e9a2d3722bb5f5b3636f307bd386ed24abafea72aeb6dd002d51eeca16df"
		or hash.sha256(0, filesize) == "9269dc68d46630c0d534bf62a299037fd3a124a6459d97692c25ffb89ccd1f08"
		or hash.sha256(0, filesize) == "0bff46518b35ddfe37f4a7820286aab829d81f1480d9eeca5aaedc9ceda6724f"
		or hash.sha256(0, filesize) == "a5bad9b8fe8d51400e44646a946f96e33421a0b7ff2bae60b3e0b5621e4fcaf1"
}
// =====================================   AS-IS  ====================================
