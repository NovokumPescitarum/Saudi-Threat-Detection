// ===================================== GENERATED ====================================

import "hash"
rule MISP_EVENT_f4473bed_8b6d_4aac_acd8_24b9eef5fa4e_PART1 : generated
{
	meta:
		MISP_EVENT_INFO = "KSA-TI Research b06458d735028b87"
		MISP_EVENT_UUID = "f4473bed-8b6d-4aac-acd8-24b9eef5fa4e"
		MISP_ORIGIN = "Automatically generated from non-Yara attribute(s)"
	condition:
		hash.sha256(0, filesize) == "8219453084f370cee43aafe27b9def6b9d3d75fb31bacd7e2fa1d82d617f26dd"
		or hash.sha256(0, filesize) == "d2d19c7f2e4a5fdcfb34b26f048077d2c4fe26637ed2c90e9e9bdf32307c377e"
		or hash.sha256(0, filesize) == "4a3aa8f4f0eb37be9778fbdf0b7dd282fc407557da61735d2ae9cfc73ee2aa81"
		or hash.sha256(0, filesize) == "65359388b49ae2a982111ebe8ac837d0f3294ceab7a712df20d0f6c19bf3029e"
		or hash.sha256(0, filesize) == "5380ffda12f97cf4d8e0fe02e0580aa1a48b4b6da95e7f8a30029ad125c51b3f"
		or hash.sha256(0, filesize) == "e9d2e4e8fac6420ca3b3a3a63a3d313dcfb236a24a11889d6923dd9b42a777d4"
		or hash.sha256(0, filesize) == "8ad63d4d30cd28391318e26f4e9464f302b0a12675a721967d4f2173ed6cfe8a"
		or hash.sha256(0, filesize) == "138a4c9cd617912c2269fae64b6b12d57e926a36c2c62f25ee05a32cdf102212"
		or hash.sha256(0, filesize) == "bb56792212abe160fff643631fb69b2081601e6310fc6669fd9d52d690ec1903"
		or hash.sha256(0, filesize) == "c9e5cbc98e91aa35a260a1f85d7a5605dc7aa8d2d0b71eb6f063147d4dfa1b5f"
		or hash.sha256(0, filesize) == "d40d730bcfa4cc7f1ee070f6ce863b03acb81af0a4d66feaec285e1205258b35"
		or hash.sha256(0, filesize) == "4a3b003994112b4dd24ac8b9cc4757f4a12576b57b3cc8f5028d85fbceb7c405"
		or hash.sha256(0, filesize) == "ffceb438127725a6a664aba5021f7625bd8c22b3f76447de91b728839136c9c3"
		or hash.sha256(0, filesize) == "0d74156089292eee308017c8e8a7550739ecb6149ff379810f7c54b1dbaabc91"
		or hash.sha256(0, filesize) == "c4e194747d9a268ff56ac1f0708745cbcc164751dcaa24f1a5a15acbe9c4d998"
		or hash.md5(0, filesize) == "b9086413e7b6a0c6a11c25d14c22615f"
		or hash.md5(0, filesize) == "7402f2f9263782a4c469570035843510"
		or hash.md5(0, filesize) == "ebdd9595b79b39f53909d862499dbc94"
		or hash.md5(0, filesize) == "481c5b5e69a08c3df206c59fd8ddc0dc"
		or hash.md5(0, filesize) == "d70ebf20e3d697897bad5bebf72ea271"
		or hash.md5(0, filesize) == "3e7a2fcef1d038d05b20148c573a6499"
		or hash.sha256(0, filesize) == "65e2dbe5c6b670f663d93fd65608470091a231803b4f449bb00e99ebf76eddb7"
}
// =====================================   AS-IS  ====================================
