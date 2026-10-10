// ===================================== GENERATED ====================================

import "hash"
rule MISP_EVENT_c1a2917c_e75a_4b35_b962_b47927fa6a7c_PART1 : generated
{
	meta:
		MISP_EVENT_INFO = "KSA-TI Molerats"
		MISP_EVENT_UUID = "c1a2917c-e75a-4b35-b962-b47927fa6a7c"
		MISP_ORIGIN = "Automatically generated from non-Yara attribute(s)"
	strings:
		$ = "hint.zapto.org" ascii wide
		$ = "natco2.no-ip.net" ascii wide
		$ = "toornt.servegame.com" ascii wide
		$ = "updateo.servegame.com" ascii wide
		$ = "egypttv.sytes.net" ascii wide
		$ = "good.zapto.org" ascii wide
		$ = "skype.servemp3.com" ascii wide
	condition:
		hash.md5(0, filesize) == "9ef9a631160b96322010a5238defc673"
		or hash.md5(0, filesize) == "e85fc76362c2e9dc7329fddda8acc89e"
		or hash.md5(0, filesize) == "7084f3a2d63a16a191b7fcb2b19f0e0d"
		or hash.md5(0, filesize) == "fc554a0ad7cf9d4f47ec4f297dbde375"
		or hash.md5(0, filesize) == "cf31aea415e7013e85d1687a1c0f5daa"
		or hash.md5(0, filesize) == "a8714aac274a18f1724d9702d40030bf"
		or hash.md5(0, filesize) == "5b740b4623b2d1049c0036a6aae684b0"
		or hash.md5(0, filesize) == "9dff139bbbe476770294fb86f4e156ac"
		or hash.md5(0, filesize) == "6350d1039742b87b7917a5e26de2c25c"
		or hash.md5(0, filesize) == "b05603938a888018d4dcdc551c4be8ac"
		or hash.md5(0, filesize) == "d9a7c4a100cfefef995785f707be895c"
		or hash.md5(0, filesize) == "b0a9abc76a2b4335074a13939c59bfc9"
		or hash.md5(0, filesize) == "16346b95e6deef9da7fe796c31b9dec4"
		or hash.md5(0, filesize) == "973b5f2a5608d243e7305ee4f9249302"
		or hash.md5(0, filesize) == "a60873e364a01870b2010518d05a62df"
		or any of them
}
// =====================================   AS-IS  ====================================
