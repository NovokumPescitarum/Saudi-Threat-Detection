// ===================================== GENERATED ====================================

import "hash"
rule MISP_EVENT_e1133353_39e6_4820_837b_847875e2706d_PART1 : generated
{
	meta:
		MISP_EVENT_INFO = "KSA-TI Unattributed"
		MISP_EVENT_UUID = "e1133353-39e6-4820-837b-847875e2706d"
		MISP_ORIGIN = "Automatically generated from non-Yara attribute(s)"
	strings:
		$ = "soholat.sa" ascii wide
		$ = "https://soholat.sa/" ascii wide
		$ = "http://krybitqsdzwmhnitvwuhvsntfgf2wrhxveyxroxpc44c6gkft2cqldyd.onion/blog/pending-6ab577d1234c6-1790277585/" ascii wide
		$ = "http://pnzruro7syvwvefx5mpo2fhzi4jftgquynsqf3vy5x3no57yp2iz4nyd.onion/company/khaled-alfagih-engineering-consultancy" ascii wide
		$ = "http://krybitqsdzwmhnitvwuhvsntfgf2wrhxveyxroxpc44c6gkft2cqldyd.onion/blog/1801921261dfee2323d1805c368ef40de7f9ea55a9c81b786eb119fdaceff14e/" ascii wide
		$ = "http://gammax6w3dkfdjfrjthtmqzsioue52vzy6lz54qy6jcvmogfpubutjyd.onion/post/B7FLS1KVkQLdkKEZEkRYn82W3bQNht1v" ascii wide
		$ = "http://z3wqggtxft7id3ibr7srivv5gjof5fwg76slewnzwwakjuf3nlhukdid.onion/blog/?post_uuid=6f4e3a42-0adb-422b-ba3e-5bd972e17938" ascii wide
		$ = "http://ctyfftrjgtwdjzlgqh4avbd35sqrs6tde4oyam2ufbjch6oqpqtkdtid.onion/10f9693f-9d25-4de6-8941-411cfe9f3020" ascii wide
		$ = "http://z3wqggtxft7id3ibr7srivv5gjof5fwg76slewnzwwakjuf3nlhukdid.onion/blog/?post_uuid=7dc6bb41-0cc2-4c0a-8b60-dffc1a57317a" ascii wide
		$ = "admin.etabeb.com" ascii wide
		$ = "https://admin.etabeb.com/login?ReturnUrl=%2f" ascii wide
	condition:
		hash.md5(0, filesize) == "b9086413e7b6a0c6a11c25d14c22615f"
		or hash.md5(0, filesize) == "7402f2f9263782a4c469570035843510"
		or hash.md5(0, filesize) == "ebdd9595b79b39f53909d862499dbc94"
		or hash.md5(0, filesize) == "481c5b5e69a08c3df206c59fd8ddc0dc"
		or hash.md5(0, filesize) == "d70ebf20e3d697897bad5bebf72ea271"
		or hash.md5(0, filesize) == "3e7a2fcef1d038d05b20148c573a6499"
		or hash.sha256(0, filesize) == "6e7d9b33f1e72ea1ede71373a604ecdb060dab7d42055179c1eede9ecd1fd239"
		or hash.sha256(0, filesize) == "f5b12772db6817f7a765a6fe7565fd3d4f87edc28e42fe3ec0244a372a410fc9"
		or hash.sha256(0, filesize) == "53f35e49eb9b271fd8cbcd3daacb525328dbf159a03dbd1c7adebe0363daa402"
		or hash.sha256(0, filesize) == "3fd810a3aa0039993393741b32287c367a9a5037a41e826906440887cdd3ed13"
		or hash.sha256(0, filesize) == "76273382e4252c1f60a2251141e108942494409c759358320735891762c0682e"
		or hash.sha256(0, filesize) == "d3561bd4aad003dc3e08157b0891860bb496b80cd6e44901692e08ab1d4e8260"
		or hash.sha256(0, filesize) == "f5ba1645694c62f527ed6ceda8c68a5c3dd92b4032439167e8e937e72803b4bd"
		or hash.sha256(0, filesize) == "7cc571aca6d8715d9aaad3d83e1bcd30467565d583db1dfe73697c5d00a1f875"
		or hash.sha256(0, filesize) == "8219453084f370cee43aafe27b9def6b9d3d75fb31bacd7e2fa1d82d617f26dd"
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
		or hash.sha256(0, filesize) == "65e2dbe5c6b670f663d93fd65608470091a231803b4f449bb00e99ebf76eddb7"
		or hash.sha256(0, filesize) == "76392303f28a7e6f1463a5fa04a19faf40d51d7be6619943a914482b0f3c7f0b"
		or hash.sha256(0, filesize) == "fa373aaa95ca512ba9595c3ab41bac892c8c79d4a31f5d74c2f3225b629de52e"
		or hash.sha256(0, filesize) == "45e16e56c81059f6758dced28a58256287785a8b0815577c1140293589aa2ae1"
		or hash.sha256(0, filesize) == "dd6d05ff31f64b9ca8ca9334a804dbee5917d6448acb026de4ca818017a04730"
		or hash.sha256(0, filesize) == "3b0c49ed1590bceffbefed150bb64545e69e792c5ad63578cc3bca5c5b96f2cb"
		or hash.sha256(0, filesize) == "19fef425c3a774e493526126a441a31971db8ac5af84c1d9eef15a272ba02ec1"
		or hash.sha256(0, filesize) == "54efee2665d3779f1be0d885409e29e6cd07fe944fa82e5d6eeb832264c7409d"
		or hash.sha256(0, filesize) == "cb29b6348ae4458b6b506f8de9336d0980bbfaf88b1d68be2771b57090d29889"
		or hash.sha256(0, filesize) == "1a992e2b36b2a9a77300b0b0fe7e9c20e127c8257fd203bb4b3eaf1e35e63ce7"
		or hash.sha256(0, filesize) == "af2decf5c5cbff0c0460ab09ad3cff497c765e3cf61e6c45f4e3b5c6a103312c"
		or hash.sha256(0, filesize) == "28a09cd68b1f4212cc61bd2d44d03d55b8bcd7df284bab56cdae8507abc90e3c"
		or hash.sha256(0, filesize) == "c6e1235d5cd01a205a191ce48c3d68e9fea620671c0c069593027a0218fad5b0"
		or hash.sha256(0, filesize) == "95ec481745c64c385c60f6c812585e5060a50e38da44bc1a9f67da3921b1a50f"
		or hash.sha256(0, filesize) == "77ead085bae72b6cb1c33c55fbd7763c4d8050798c55af3132c3b904084eeb8a"
		or hash.sha256(0, filesize) == "ad2b019cf346b8b4e6b2174a95b1d897ce736087bd06066f31a9d7fd72283e9f"
		or hash.sha256(0, filesize) == "b714f590380e5be8233cd60a4f212d949aff27b3a980e6d644c84b0120dd25b3"
		or hash.sha256(0, filesize) == "648b34fa952a2806d9f4c272f8bfbadc45c0c370c3d7c2ff0c7ffbb015237ce1"
		or hash.sha256(0, filesize) == "5fff21af95bd38b8c11dd73342a55acb75e91ff1936ed0ccb06af28400ef87d4"
		or any of them
}
// =====================================   AS-IS  ====================================
