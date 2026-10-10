// ===================================== GENERATED ====================================

import "hash"
rule MISP_EVENT_7f1c7f72_9267_4567_9ad2_cc11fa364151_PART1 : generated
{
	meta:
		MISP_EVENT_INFO = "KSA-TI Agrius (BlackShadow / Pink Sandstorm)"
		MISP_EVENT_UUID = "7f1c7f72-9267-4567-9ad2-cc11fa364151"
		MISP_ORIGIN = "Automatically generated from non-Yara attribute(s)"
	condition:
		hash.md5(0, filesize) == "f784bae890214dab5563610632babe4a"
		or hash.md5(0, filesize) == "363ecd7d395998373d031c3696c2f871"
		or hash.md5(0, filesize) == "2e7178f44b119d7214b239ee335f96be"
		or hash.md5(0, filesize) == "f20f5b077c723c9dea043590b33c6b81"
		or hash.md5(0, filesize) == "33180fda80e647d863db5f9d55d2c96b"
		or hash.md5(0, filesize) == "595a153aefa32eb096fc469b38890e6d"
		or hash.md5(0, filesize) == "01708746934ae8e163f6a67893a0f414"
		or hash.sha1(0, filesize) == "820ad7e30b4c54692d07b29361aecd0bb14df3be"
		or hash.sha1(0, filesize) == "b3b1edd6b80af0cdadadd1ee1448056e6e1b3274"
		or hash.sha1(0, filesize) == "3228e6bc8c738781176e65ebbc0eb52020a44866"
		or hash.sha1(0, filesize) == "5485c627922a71b04d4c78fbc25985cdb163313b"
		or hash.sha1(0, filesize) == "1a62031bbb2c3f55d44f59917fd32e4ed2041224"
		or hash.sha1(0, filesize) == "db11cbffe30e0094d6de48259c5a919c1eb57108"
		or hash.sha1(0, filesize) == "1aae62acee3c04a6728f9edc3756fabd6e342252"
		or hash.sha256(0, filesize) == "9ccf9817da1ee8c1ab33a364a3c03a28769ab68a42c437295dae47448a6c5138"
		or hash.sha256(0, filesize) == "c96d84a4064a65f87209756d59399254b41bb3a76f3b825f2d606773903665c5"
		or hash.sha256(0, filesize) == "5f3b84ad75e068727823c5349e475e4ab5516925d344269d678e94df442537c2"
		or hash.sha256(0, filesize) == "a5330b1add40a30dccab27294736fcd906ef35ddb811d67cb8379f3ea0957e91"
		or hash.sha256(0, filesize) == "91a9180a9cf7674c34ed53a8aa4e36b798334d1f448aeaf1afb9add4fd322b6e"
		or hash.sha256(0, filesize) == "cc1910d0ec7e7a49321a440ed95cd776651311192c70aa47d76ce9345f08a0c9"
		or hash.sha256(0, filesize) == "559728144a911d13ab978473091e68581d91bf426e84f500a2026537c20b0ec3"
}
// =====================================   AS-IS  ====================================
