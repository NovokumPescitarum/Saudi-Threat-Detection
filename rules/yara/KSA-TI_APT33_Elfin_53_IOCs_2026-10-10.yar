// ===================================== GENERATED ====================================

import "hash"
rule MISP_EVENT_d769f930_5c1f_48bc_940c_4c836d6b6d7c_PART1 : generated
{
	meta:
		MISP_EVENT_INFO = "KSA-TI APT33/Elfin (53 IOCs) 2026-10-10"
		MISP_EVENT_UUID = "d769f930-5c1f-48bc-940c-4c836d6b6d7c"
		MISP_ORIGIN = "Automatically generated from non-Yara attribute(s)"
	strings:
		$ = "www.chromup.com" ascii wide
		$ = "www.securityupdated.com" ascii wide
		$ = "managehelpdesk.com" ascii wide
		$ = "microsoftupdated.com" ascii wide
		$ = "microsoftupdated.net" ascii wide
		$ = "osupd.com" ascii wide
		$ = "alsalam.ddns.net" ascii wide
		$ = "boeing.servehttp.com" ascii wide
		$ = "mywinnetwork.ddns.net" ascii wide
		$ = "ngaaksa.ddns.net" ascii wide
		$ = "ngaaksa.sytes.net" ascii wide
		$ = "syn.broadcaster.rocks" ascii wide
		$ = "vinnellarabia.myftp.org" ascii wide
		$ = "www.googlmail.net" ascii wide
	condition:
		hash.md5(0, filesize) == "8e67f4c98754a2373a49eaf53425d79a"
		or hash.md5(0, filesize) == "0ccc9ec82f1d44c243329014b82d3125"
		or hash.md5(0, filesize) == "fb21f3cea1aa051ba2a45e75d46b98b8"
		or hash.md5(0, filesize) == "0753857710dcf96b950e07df9cdf7911"
		or hash.md5(0, filesize) == "10f58774cd52f71cd4438547c39b1aa7"
		or hash.md5(0, filesize) == "1381148d543c0de493b13ba8ca17c14f"
		or hash.md5(0, filesize) == "32a9a9aa9a81be6186937b99e04ad4be"
		or hash.md5(0, filesize) == "3e8a4d654d5baa99f8913d8e2bd8a184"
		or hash.md5(0, filesize) == "3f5329cf2a829f8840ba6a903f17a1bf"
		or hash.md5(0, filesize) == "59d0d27360c9534d55596891049eb3ef"
		or hash.md5(0, filesize) == "663c18cfcedd90a3c91a09478f1e91bc"
		or hash.md5(0, filesize) == "6a0f07e322d3b7bc88e2468f9e4b861b"
		or hash.md5(0, filesize) == "6b41980aa6966dda6c3f68aeeb9ae2e0"
		or hash.md5(0, filesize) == "6f1d5c57b3b415edc3767b079999dd50"
		or hash.md5(0, filesize) == "797bc06d3e0f5891591b68885d99b4e1"
		or hash.md5(0, filesize) == "8e6d5ef3f6912a7c49f8eb6a71e18ee2"
		or hash.md5(0, filesize) == "a272326cb5f0b73eb9a42c9e629a0fd8"
		or hash.md5(0, filesize) == "a2af2e6bbb6551ddf09f0a7204b5952e"
		or hash.md5(0, filesize) == "a80c7ce33769ada7b4d56733d02afbe5"
		or hash.md5(0, filesize) == "a813dd6b81db331f10efaf1173f1da5d"
		or hash.md5(0, filesize) == "aa63b16b6bf326dd3b4e82ffad4c1338"
		or hash.md5(0, filesize) == "ae47d53fe8ced620e9969cea58e87d9a"
		or hash.md5(0, filesize) == "ae870c46f3b8f44e576ffa1528c3ea37"
		or hash.md5(0, filesize) == "b12faab84e2140dfa5852411c91a3474"
		or hash.md5(0, filesize) == "b189b21aafd206625e6c4e4a42c8ba76"
		or hash.md5(0, filesize) == "b3d73364995815d78f6d66101e718837"
		or hash.md5(0, filesize) == "b5f69841bf4e0e96a99aa811b52d0e90"
		or hash.md5(0, filesize) == "b681aa600be5e3ca550d4ff4c884dc3d"
		or hash.md5(0, filesize) == "bbdd6bb2e8827e64cd1a440e05c0d537"
		or hash.md5(0, filesize) == "c02689449a4ce73ec79a52595ab590f6"
		or hash.md5(0, filesize) == "c2d472bdb8b98ed83cc8ded68a79c425"
		or hash.md5(0, filesize) == "c2fbb3ac76b0839e0a744ad8bdddba0e"
		or hash.md5(0, filesize) == "c55b002ae9db4dbb2992f7ef0fbc86cb"
		or hash.md5(0, filesize) == "c57c5529d91cffef3ec8dadf61c5ffb2"
		or hash.md5(0, filesize) == "c66422d3a9ebe5f323d29a7be76bc57a"
		or hash.md5(0, filesize) == "c6f2f502ad268248d6c0087a2538cad0"
		or hash.md5(0, filesize) == "d01781f1246fd1b64e09170bd6600fe1"
		or hash.md5(0, filesize) == "de7a44518d67b13cda535474ffedf36b"
		or hash.md5(0, filesize) == "de9e3b4124292b4fba0c5284155fa317"
		or any of them
}
// =====================================   AS-IS  ====================================
