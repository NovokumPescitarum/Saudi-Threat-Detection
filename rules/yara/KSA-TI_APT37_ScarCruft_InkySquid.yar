// ===================================== GENERATED ====================================

import "hash"
rule MISP_EVENT_54ce7afa_9c73_462e_90fe_257ec48939f2_PART1 : generated
{
	meta:
		MISP_EVENT_INFO = "KSA-TI APT37 (ScarCruft / InkySquid)"
		MISP_EVENT_UUID = "54ce7afa-9c73-462e-90fe-257ec48939f2"
		MISP_ORIGIN = "Automatically generated from non-Yara attribute(s)"
	condition:
		hash.md5(0, filesize) == "02681a7fe708f39beb7b3cf1bd557ee9"
		or hash.md5(0, filesize) == "c781f5fad9b47232b3606e4d374900cd"
		or hash.md5(0, filesize) == "032ed0cd234f73865d55103bf4ceaa22"
		or hash.md5(0, filesize) == "22aaf617a86e026424edb7c868742495"
		or hash.md5(0, filesize) == "07d2200f5c2d03845adb5b20841faa94"
		or hash.md5(0, filesize) == "1f5ac2f1744ed9c3fd01fe72ee8d334f"
		or hash.md5(0, filesize) == "4d20f7311f4f617104f559a04afd2fbf"
		or hash.md5(0, filesize) == "03e5e566c1153cb1d18b8bc7c493025f"
		or hash.md5(0, filesize) == "c66ef71830341bb99d30964a8089a1fc"
		or hash.md5(0, filesize) == "5999e01b83aa1cc12a2ad6a0c0dc27c3"
		or hash.md5(0, filesize) == "4d3c34a3070643c225be1dbbb3457ad4"
		or hash.md5(0, filesize) == "0790f1d7a1b9432aa5b8590286eb8b95"
		or hash.md5(0, filesize) == "04371bf88b598b56691b0ad9da08204b"
		or hash.md5(0, filesize) == "e8b23cfc805353f55ed67cf0af58f305"
		or hash.md5(0, filesize) == "5380a173757e67d9b12f316771012768"
		or hash.md5(0, filesize) == "ec0e77b57cb9dd7a04ab6e453810937c"
		or hash.md5(0, filesize) == "25701492a18854ffdb05317ec7d19c29"
		or hash.md5(0, filesize) == "172b4dc27e41e4a0c84a803b0b944d3e"
		or hash.md5(0, filesize) == "7149c205d634c4d17dae33fffb8a68ab"
		or hash.md5(0, filesize) == "a76c4a79e6ff73bfd7149a49852e8916"
		or hash.md5(0, filesize) == "f63fc2d11fcebd37be3891def5776f6c"
		or hash.md5(0, filesize) == "899e90a0851649a5c270d1f78baf60f2"
		or hash.md5(0, filesize) == "e88f7f285163d0c080c8d3e525b35ab3"
		or hash.md5(0, filesize) == "d7c94c5ba028dc22a570f660b8dee5b9"
		or hash.md5(0, filesize) == "a6bd2cf7bccf552febb8e8347d07529a"
		or hash.md5(0, filesize) == "7a338d08226f5a38353385c8a5dec746"
		or hash.md5(0, filesize) == "46f66d2d990660661d00f5177306309c"
		or hash.md5(0, filesize) == "5e0e11bca0e94914e565c1dcc1ee6860"
		or hash.md5(0, filesize) == "4c2016df6b546326d67ac2a79dea1343"
}
// =====================================   AS-IS  ====================================
