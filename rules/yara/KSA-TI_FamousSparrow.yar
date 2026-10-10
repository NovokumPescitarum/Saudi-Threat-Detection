// ===================================== GENERATED ====================================

import "hash"
rule MISP_EVENT_602eab0c_c5eb_4ef2_8dc9_dd9dc35667c8_PART1 : generated
{
	meta:
		MISP_EVENT_INFO = "KSA-TI FamousSparrow"
		MISP_EVENT_UUID = "602eab0c-c5eb-4ef2-8dc9-dd9dc35667c8"
		MISP_ORIGIN = "Automatically generated from non-Yara attribute(s)"
	strings:
		$ = "130.94.101.82" ascii wide
		$ = "149.104.87.228" ascii wide
		$ = "149.104.90.203" ascii wide
		$ = "38.54.57.17" ascii wide
		$ = "38.60.197.55" ascii wide
		$ = "38.60.209.106" ascii wide
		$ = "38.60.224.235" ascii wide
		$ = "38.60.224.51" ascii wide
		$ = "38.60.241.127" ascii wide
		$ = "38.60.241.193" ascii wide
		$ = "38.60.241.65" ascii wide
		$ = "77.111.101.40" ascii wide
		$ = "91.148.134.115" ascii wide
		$ = "140.99.164.199" ascii wide
		$ = "216.238.92.2" ascii wide
		$ = "216.238.105.53" ascii wide
		$ = "216.238.110.120" ascii wide
		$ = "216.238.121.164" ascii wide
	condition:
		hash.md5(0, filesize) == "006f22e5e419d349e6459d0d5610105f"
		or hash.md5(0, filesize) == "b162026b29d75a870543ad9c044c28c2"
		or hash.md5(0, filesize) == "00d27e62deeb30658d99631f5b87ffa2"
		or hash.md5(0, filesize) == "59f241ae36899c9283a898bbaec7de5e"
		or hash.md5(0, filesize) == "f44b04364b2b33a84adc172f337aa1d1"
		or hash.md5(0, filesize) == "fdf677939cb36c29a6b4b139fad5acde"
		or hash.md5(0, filesize) == "c40a2f5f25157e6a434602017531d608"
		or hash.md5(0, filesize) == "2a0378d98ca30965157eb7306aeeb494"
		or hash.md5(0, filesize) == "badc4892e4220f8bcf245881347102f1"
		or hash.md5(0, filesize) == "e74324813227625bd6ea9b844e53860b"
		or hash.md5(0, filesize) == "34afabc8e16b60dad902d910743d9fe9"
		or hash.md5(0, filesize) == "842d309028db1a1aeeecfbaa3ea9ae0a"
		or hash.md5(0, filesize) == "cbfeb134d0c76e8d53076e0e20e09559"
		or hash.md5(0, filesize) == "63a9eb049c8ccb3eb19c41a21ee7b444"
		or hash.md5(0, filesize) == "37d161062265a92ad64ef708654761ef"
		or hash.md5(0, filesize) == "2764315df9c6022802df9bf2b7f08e90"
		or hash.md5(0, filesize) == "8f809903566b0240202d85e834aa13c1"
		or hash.md5(0, filesize) == "23fa4f920f094fae83dbec708c6f8e42"
		or hash.md5(0, filesize) == "002709cee9f06e4b46998f9955f4f2ba"
		or hash.md5(0, filesize) == "f5cf8c9d1df971f48fbe87a7f0ee6150"
		or hash.md5(0, filesize) == "e6a65bccc172345cd69f04d4ef4d5ee0"
		or hash.md5(0, filesize) == "db5e52cc71a88876c0216d994f247d4c"
		or hash.md5(0, filesize) == "24fd6cfd63b65187a3f38c63505ab048"
		or hash.md5(0, filesize) == "e7a7daa3ee59bd9ca701bf95f2b9c958"
		or hash.md5(0, filesize) == "54b419c2cac1a08605936e016d460697"
		or hash.md5(0, filesize) == "c9ccc4c525c301c106684c17db2088bc"
		or hash.md5(0, filesize) == "357b0ec0fbd81e25f68cbb81444f01f6"
		or hash.md5(0, filesize) == "8037d1d022ccc182d75b12b1c533df7d"
		or hash.md5(0, filesize) == "b44217b8e6696a692345367105456222"
		or hash.md5(0, filesize) == "9aefe01eafbec9361ca4030fcd17581e"
		or hash.md5(0, filesize) == "922c1edb47fba94b548edca863165fb1"
		or hash.md5(0, filesize) == "a7a6cae75e38283810082ad2887f1d26"
		or hash.md5(0, filesize) == "aa64f057943cb5cb047badae310714c1"
		or hash.sha1(0, filesize) == "fdc44057e87d7c350e6df84bb72541236a770ba2"
		or hash.sha1(0, filesize) == "bb2f5b573ac7a761015daad0b7ff03b294dc60f6"
		or hash.sha1(0, filesize) == "4df896624695ea2780552e9ea3c40661dc84efc8"
		or hash.sha1(0, filesize) == "b9601e60f87545441bf8579b2f62668c56507f4a"
		or hash.sha1(0, filesize) == "c36ecd2e0f38294e1290f4b9b36f602167e33614"
		or hash.sha1(0, filesize) == "e2b0851e2e281cc7bca3d6d9b2fa0c4b7ac5a02b"
		or hash.sha1(0, filesize) == "76c430b55f180a85f4e1a1e40e4a2ea37db97599"
		or hash.sha1(0, filesize) == "873f98caf234c3a8a9db18343dad7b42117e85d4"
		or hash.sha1(0, filesize) == "23e228d5603b4802398b2e7419187aef71ff9dd5"
		or hash.sha1(0, filesize) == "2560b7e28b322bb7a56d0b1da1b2652e1efe76ea"
		or hash.sha1(0, filesize) == "5f1553f3af9425ef5d68341e991b6c5ec96a82eb"
		or hash.sha1(0, filesize) == "0dc20b2f11118d5c0cc46b082d7f5dc060276157"
		or hash.sha1(0, filesize) == "db1591c6e23160a94f6312ca46da2d0bb243322c"
		or hash.sha1(0, filesize) == "7d66b550ea68a86fcc0958e7c159531d4431b788"
		or hash.sha1(0, filesize) == "d6d32a1f17d48fe695c0778018c0d51626db4a3b"
		or hash.sha1(0, filesize) == "aa823148eea6f43d8eb9bf20412402a7739d91c2"
		or hash.sha1(0, filesize) == "ebc93a546bcdf6cc1eb61d7174bcb85407bbd892"
		or hash.sha1(0, filesize) == "ef189737fb7d61b110b9293e8838526dce920127"
		or hash.sha1(0, filesize) == "5265e8edc9b5f7dd00fc772522511b8f3be217e3"
		or hash.sha1(0, filesize) == "d03fd329627a58b40e805f4f55b5d821063ac27f"
		or hash.sha1(0, filesize) == "f35ce62abeedfb8c6a38ceac50a250f48c41e65e"
		or hash.sha1(0, filesize) == "0925f24082971f50edd987d82f708845a6a9d7c9"
		or hash.sha1(0, filesize) == "3a395daaf518be113fcff2e5e48acd9b9c0de69d"
		or hash.sha1(0, filesize) == "a91b42e5062fef608f285002debaff9358162b25"
		or hash.sha1(0, filesize) == "1b06e877c2c12d74336e7532bc0ecf761e5fa5d4"
		or hash.sha1(0, filesize) == "5df3c882db6be14887182b7439b72a86bd28b83f"
		or hash.sha1(0, filesize) == "cc350ba25947b7f9ec5d11ea8269407c0fd74095"
		or hash.sha1(0, filesize) == "c26f04790c6fb7950d89ab1b08207ace01efb536"
		or hash.sha1(0, filesize) == "99e7070b5af24a0fe1e6febe5954b03cb385e91f"
		or hash.sha1(0, filesize) == "9aa9ff61bc63ccab9074fe837f39c980ca9ddc8c"
		or hash.sha1(0, filesize) == "44f0a22b143b79fa760bf31e14c8fff714c8a2a1"
		or hash.sha1(0, filesize) == "3209689e509205ccdb7e49062b7b407ddc23cac1"
		or hash.sha1(0, filesize) == "52c6646759cf6037bb17466203631c4bd794532f"
		or hash.sha256(0, filesize) == "f51dc5e1848daee4e607d46faa25033e1151060cd3482ad4439754440d6c4c01"
		or hash.sha256(0, filesize) == "f23e5391656b178bc0ab510b0fca6ffbd963cf94870c82a5920f0f338f561f18"
		or hash.sha256(0, filesize) == "e9f2f42ea3611096879f4152a7d78bb3a78a4dbead1c3b7e366dce485207551f"
		or hash.sha256(0, filesize) == "e5f7bbfc187264336dea5dfebfb5a7dd1e7fcdcc9692db55fbe6eb4d28f027bc"
		or hash.sha256(0, filesize) == "b60404c1299e69df029d9817dcf69f9fe325ecc990e16bc7758f56ce5714184b"
		or hash.sha256(0, filesize) == "b379d07ba81d4190490d9893b2d6d830ff594e042dce26053ef07794d0403787"
		or hash.sha256(0, filesize) == "74f95f5d36172fda16eef5bede65023f5e0486fc87f81ebfdcd150187e63d004"
		or hash.sha256(0, filesize) == "8bbc395a7a0faff074c6e31c7da37bf1540a4e7ec3d80870f8d6bd1f5d4cecbb"
		or hash.sha256(0, filesize) == "c69534bb3e6d4e1c9b21f9e4745f6fb002cbcd3ab83f9ad208eb7bb135401062"
		or hash.sha256(0, filesize) == "4c7ae604ad1af90ea155865cb28fd7ccd6371f5ac172de6014b328514d4618e7"
		or hash.sha256(0, filesize) == "0e74d57f572e384ad179ad8aa094cbdc92a6abbcc77eeb658fc05743ffd94e68"
		or hash.sha256(0, filesize) == "222d68c03d96d230bc3829e86be8821f32960375b70388028a705a4986b8d9c6"
		or hash.sha256(0, filesize) == "8dfaa1f579de14bca8bb27c54a57dd87646a835969766ca9ddb81ecd9329f4e4"
		or hash.sha256(0, filesize) == "e0ff727c5feb3352f0bb6df91bcf2b3100203e5777c8b49b3913fcec0dbbd260"
		or hash.sha256(0, filesize) == "bc2b8196d8c966e84c255d0d1c7908541104446e3fc51f52318aac4239bbb4c4"
		or hash.sha256(0, filesize) == "03241adc63e5a204dcec26915f4df076a8121fa7827edfdc36b75e4803c2f019"
		or hash.sha256(0, filesize) == "1215584b4fa69130799f6cf5efe467f380dc68b14ed2c76f63ca6b461ad57246"
		or hash.sha256(0, filesize) == "773635768e738bec776dfd7504164b3596e5eee344757dd1ac9a1ad19b452c86"
		or hash.sha256(0, filesize) == "67d7962eaec2c785d7a6db8502c74e6ccd95445d366e370fa9fe6743d68cb42c"
		or hash.sha256(0, filesize) == "90af57e976aea91030579b9761e5265251986b707550ca1b793191e2818bad92"
		or hash.sha256(0, filesize) == "f61a113f6de19f2c821b89d934268621cf2410278155f173c8682e524b450f21"
		or hash.sha256(0, filesize) == "f2434d7f2427ee2f3a1be4ab0922fb73ac2ceaa494c73790af71024453ce0c9c"
		or hash.sha256(0, filesize) == "c57fd715bcb6d5ece60745d036496ac37e0c13f14098776c9168c0381a01409f"
		or hash.sha256(0, filesize) == "dd5a6c162eff8103f6e06149faf1287feeb6dbbbb9bbca031145767fd69ce500"
		or hash.sha256(0, filesize) == "24dc94e01592a29c90fd875dcdfa095ed6e1dff6db4e517b48a2f89db467aa28"
		or hash.sha256(0, filesize) == "edc3ab9bc87402a5e7de43b7b2e247fdd4e134b9220d91f84934362cce34b827"
		or hash.sha256(0, filesize) == "dd3dffb09fd1df4ea2ae38023e5c256855dfc9bcf9913d775f65365e2acae166"
		or hash.sha256(0, filesize) == "b68c8dff2ca0944c7e6c94d184d8219c08c020eb349ff9e0a7f49bc6a6effdaf"
		or hash.sha256(0, filesize) == "973a692e6240bf4ce3c14e6ca13755c7e473c7722513d7a6e811a08cf2ae0e10"
		or hash.sha256(0, filesize) == "1cca1555b3ce3dbe37e17f32c91441886fb113a3d5e8da1c4ec5e523f8719fa5"
		or hash.sha256(0, filesize) == "63cf1e1e7ea20a69f8a6b9d16468673b92cfe2560ad1012422ec3001a7e837cf"
		or hash.sha256(0, filesize) == "80a7ff01de553cb099452cb9fac5762caf96c0c3cd9c5ad229739da7f2a2ca72"
		or hash.sha256(0, filesize) == "41128b82fa12379034b3c42bdecf8e3b435089f19a5d57726a2a784c25e9d91f"
		or hash.sha256(0, filesize) == "1ce7895cee6dfbc182486f7c2dff87281ba0b57a85febeb1a0196d480d032936"
		or hash.sha256(0, filesize) == "abbf9c57ad3068c8aafaf443297e9448e8657b6ac16e1a8bdde5ba87254708e1"
		or hash.sha256(0, filesize) == "d53346b5c8c6c76e7bc0407410a58328a1e214a4d359e558380963d29a35f71b"
		or hash.sha256(0, filesize) == "5ad73e8bd5bde7808cfa39d3ada411a2e5a51278dcc7b543f2f5b5abb0c4ea27"
		or hash.sha256(0, filesize) == "d057034675befc1b4c2ae4132c4d169201c9abfbae79181185d45ca6721e43cc"
		or hash.sha256(0, filesize) == "95dff799b2fffe128fb5e8f3bae0a0ec5bc5b181567165ac50860beac9230fcf"
		or hash.sha256(0, filesize) == "b87247a9ab8994e18486970c8c393593143b8775d75305b8b244c58a1294790c"
		or hash.sha256(0, filesize) == "e0b6f8535e19f0a4938e3317de0c4493ecea17aa906fd0454805ba2086cbf3a8"
		or hash.sha256(0, filesize) == "72677119b8bf3e2d23f22150c7b364fea9248819c36e97db015414586285591d"
		or hash.sha256(0, filesize) == "3c771cf5f74a62a0c0d825f99dbe322ec261b4cc988006ada3a4b829b09ba43e"
		or any of them
}
// =====================================   AS-IS  ====================================
