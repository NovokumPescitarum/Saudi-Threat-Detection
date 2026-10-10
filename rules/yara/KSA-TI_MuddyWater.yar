// ===================================== GENERATED ====================================

import "hash"
rule MISP_EVENT_3c6a994f_d67f_4841_9e57_3792bc945890_PART1 : generated
{
	meta:
		MISP_EVENT_INFO = "KSA-TI MuddyWater"
		MISP_EVENT_UUID = "3c6a994f-d67f-4841-9e57-3792bc945890"
		MISP_ORIGIN = "Automatically generated from non-Yara attribute(s)"
	strings:
		$ = "webmail.lax.co.il" ascii wide
		$ = "instance-uwct38-relay.screenconnect.com" ascii wide
		$ = "instance-sy9at2-relay.screenconnect.com" ascii wide
		$ = "http://graphixo.net/wp-includes/utf8.php" ascii wide
		$ = "http://ksahosting.net/wp-includes/utf8.php" ascii wide
		$ = "http://assignmenthelptoday.com/wp-includes/utf8.php" ascii wide
		$ = "https://assignmenthelptoday.com/wp-includes/utf8.php" ascii wide
		$ = "https://annapolisfirstlimo.com/editob.nvd" ascii wide
		$ = "http://185.183.96.61:80/downloadc.php?key=" ascii wide
		$ = "http://185.183.98.242/default.php" ascii wide
		$ = "https://webhook.site/f4c2dba3-bdba-44a3-b8b8-f292b6fb8a7b" ascii wide
		$ = "https://webmail.lax.co.il/owa/auth/Current/Script/jquery-3.5.1.min.js" ascii wide
		$ = "https://ws.onehub.com/files/gxvrqwzu" ascii wide
		$ = "https://webhook.site/861f0c6f-238a-4878-8e44-0ca078ad9b2c" ascii wide
		$ = "https://webhook.site/7c1564f7-4e3c-4082-b1f8-3b52da3d9941" ascii wide
		$ = "https://ws.onehub.com/files/7w1372el" ascii wide
		$ = "https://ws.onehub.com/files/94otjyvd" ascii wide
	condition:
		hash.md5(0, filesize) == "5ef459908d5be0672b02cdfe4f606989"
		or hash.md5(0, filesize) == "2c3a634953a9a2c227a51e8eeac9f137"
		or hash.md5(0, filesize) == "269afae11cc9837e732019a03fa02fab"
		or hash.md5(0, filesize) == "1cd71f39ff9fb3bf269440b63c717195"
		or hash.md5(0, filesize) == "7ed6c5e8c3ec4f9499eb793d69a06758"
		or hash.md5(0, filesize) == "b9ee416f2d9557be692abf448bf2f937"
		or hash.md5(0, filesize) == "a9706c01de9364eab210ea73296bfe71"
		or hash.md5(0, filesize) == "584479a1958a73720c4aebb52c59b21e"
		or hash.md5(0, filesize) == "32156247f900883d5106795ec103a624"
		or hash.md5(0, filesize) == "4022bbb9df5d86226bd9a89f361c94b9"
		or hash.md5(0, filesize) == "b100c0cfbe59fa66cbb75de65c505ce2"
		or hash.md5(0, filesize) == "46f911014f1202e17936f627f34e6165"
		or hash.md5(0, filesize) == "50ac74eb38d6fa07d9f5e788d61a92cd"
		or hash.md5(0, filesize) == "66c783e41480e65e287081ff853cc737"
		or hash.md5(0, filesize) == "e18228bee6f1cf12eaf1bb4d5be587bf"
		or hash.md5(0, filesize) == "9d0bfb81f450de8364327a4aaa67d9b3"
		or hash.md5(0, filesize) == "1d6f241798818e6fdc03015d01e1e680"
		or hash.md5(0, filesize) == "dbadc2caee829baf5531703f6741a9d3"
		or hash.md5(0, filesize) == "bbe9bb47f8dd8ba97250bf7f13187ab6"
		or hash.md5(0, filesize) == "2e6169253a87a9d67037b1a238d46365"
		or hash.md5(0, filesize) == "5c000ef1e5c6f50cc32c6d70837bd1b2"
		or hash.md5(0, filesize) == "fbe65cd962fc97192d95c40402eee594"
		or hash.md5(0, filesize) == "4d161d67c8cb5c44902b7ebaef131aaf"
		or hash.md5(0, filesize) == "2534e46be860170f2237c65749af4435"
		or hash.md5(0, filesize) == "01160fd8afe8f133b7a95755ead39679"
		or hash.md5(0, filesize) == "2e7b4ae4baa704588248b425b8e027bf"
		or hash.md5(0, filesize) == "ee2d1e570be5d53a5c970339991e2fd7"
		or hash.md5(0, filesize) == "2c3d8366b6ed1aa5f1710d88b3adb77d"
		or hash.md5(0, filesize) == "b07d9eca8af870722939fd87e928e603"
		or hash.md5(0, filesize) == "c938b18056ec17ac00bf0083844eafd8"
		or hash.md5(0, filesize) == "b4e4707a23708f436b481a0ebcbaa849"
		or hash.md5(0, filesize) == "2cd569dafe4f537150f0416b021c30ab"
		or hash.md5(0, filesize) == "e8e84ac1ae83a45c260df146e97cb1cb"
		or hash.md5(0, filesize) == "a8fce1e8e89053e143b5431cfa5209cb"
		or hash.md5(0, filesize) == "960594cbdf938bcb03bd0637843d9154"
		or hash.sha1(0, filesize) == "dc7fca6a34a3a65cf5df6c17435fc5f2f1c62b93"
		or hash.sha1(0, filesize) == "56b3ecdf2a3241f7f1b67f797721e06366bbc063"
		or hash.sha1(0, filesize) == "0984f359c1f8c85da5a0662448a4fedab4c524e5"
		or hash.sha1(0, filesize) == "60b5b41bd598fd844630fdf609539fc854437392"
		or hash.sha1(0, filesize) == "9804af6865f0ffcc8143761863160b6e8a004ee8"
		or hash.sha1(0, filesize) == "735698c8fbc49cfea50dded4ad6b8c719c148882"
		or hash.sha1(0, filesize) == "a80c650cd1a486e077b2e1867f36f553cb682a41"
		or hash.sha1(0, filesize) == "3cf40758a15faf5037a7fcb6c8d6c322ec54dfc1"
		or hash.sha1(0, filesize) == "c58370b4114d4d493e141a66cd1484573ccf02b5"
		or hash.sha1(0, filesize) == "707c251833db0fb7c17c79413ddaebcb54cdb0fc"
		or hash.sha1(0, filesize) == "f228e772a31b4fc160cb59cf5627224613f10941"
		or hash.sha256(0, filesize) == "a1282dde503e911d5653e1d9d1214e4780e61c96d1530c3a1be22d88a81dcf5f"
		or hash.sha256(0, filesize) == "61072ae06a5e25194e7bf6297026b54ae52fcfc14787ead8866866d8098a1fa3"
		or hash.sha256(0, filesize) == "9e65ccf31a2413bf43695ba04c5402ed235ce456563758d6e3a3ad2126e3734a"
		or hash.sha256(0, filesize) == "8bbed7013e339cca41cf85a0788ef0fc250b54515a038eff6d4838a16be047d7"
		or hash.sha256(0, filesize) == "b154d3fd88767776b1e36113c479ef3487ceda0f6e4fc80cef85ba539a589555"
		or hash.sha256(0, filesize) == "56cf06c3230aefea1d85b42a59fb42d514681f35350aa907e84603b2f426ae88"
		or hash.sha256(0, filesize) == "19ec3f16a42ae58ab6feddc66d7eeecf91d7c61a0ac9cdc231da479088486169"
		or hash.sha256(0, filesize) == "7c5e759fc13b20fef2eae64f5ceef834d575093a539435f22d7f8bf88e6b48e3"
		or hash.sha256(0, filesize) == "31a35e3b87a7f81449d6f3e195dc0660b5dae4ac5b7cd9a65a449526e8fb7535"
		or hash.sha256(0, filesize) == "3e4e179a7a6718eedf36608bd7130b62a5a464ac301a211c3c8e37c7e4b0b32b"
		or hash.sha256(0, filesize) == "5bfb635c43eb73f25f4e75961a715b96fa764bbe096086fc1e037a7869c7878b"
		or hash.sha256(0, filesize) == "77505dcec5d67cc0f6eb841f50da7e7c41a69419d50dc6ce17fffc48387452e1"
		or hash.sha256(0, filesize) == "b2f429efdb1801892ec8a2bcdd00a44d6ee31df04721482a1927fc6df554cdcf"
		or any of them
}
// =====================================   AS-IS  ====================================
