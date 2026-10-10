// ===================================== GENERATED ====================================

import "hash"
rule MISP_EVENT_4007401d_9ffc_495a_a6d3_dafa7df77238_PART1 : generated
{
	meta:
		actor = "Inception (Cloud Atlas)"
		attack_techniques = "T1003,T1003.001,T1003.004,T1003.005,T1005,T1016,T1027,T1033,T1041,T1057,T1059,T1059.001,T1059.005,T1069,T1069.002,T1070,T1070.004,T1071,T1071.001,T1082,T1083,T1090,T1090.003,T1102,T1105"
		MISP_EVENT_INFO = "KSA-TI Inception (Cloud Atlas)"
		MISP_EVENT_UUID = "4007401d-9ffc-495a-a6d3-dafa7df77238"
		MISP_ORIGIN = "Automatically generated from non-Yara attribute(s)"
	condition:
		hash.sha256(0, filesize) == "f2c4281e4d6c11173493b759adfb0eb798ce46650076e7633cf086b6d59fdb98"
		or hash.sha256(0, filesize) == "482aeb3db436e8d531b2746a513fe9a96407cf4458405680a49605e136858ec5"
		or hash.sha256(0, filesize) == "2f97374c76ae10c642a57a8b13d25cbdc070c9098c951ea418d1533ac01dc23c"
		or hash.sha256(0, filesize) == "3cf2bda35e88c59bb89e7fdc8fcfd4c46b2b9186e61325d2924e049d775b741f"
		or hash.sha256(0, filesize) == "c0e154b10d70b99b5616a2eda6bfe188a49f85ed3aa92d48ec9ce709df9d563f"
		or hash.sha256(0, filesize) == "a4194555b19ea32680cc23f8f7d42da02b82eba8b64cb5f4630110f4e2c1ddf3"
		or hash.sha256(0, filesize) == "59066dc428cde7cc55f3c24c2658d3e288f3f072811d86243a85af14bd482744"
		or hash.sha256(0, filesize) == "4cb6e224b6b03a2f6ac1ac23e6bf097067018b90493ee94f210f66fbbbbdce77"
		or hash.sha256(0, filesize) == "2233c0d4030cc728c2219b1e9c4c05cb262e2ddc7f4ac2f2924767396418c25a"
		or hash.sha256(0, filesize) == "7fcf7c1dad362283d0a27993df4764e2bbb11857842b80f63d63449b9f2f1fa4"
		or hash.sha256(0, filesize) == "d9fc6504c8970fefc441c77965937c382b029f1278918d1f54d196859e9f6e7c"
		or hash.sha256(0, filesize) == "3e7b066c26ba98d285a41043c739be8767606d9df057ee2f7bcddb7862c00711"
		or hash.sha256(0, filesize) == "c5d1de206445f508c1af5f213e46b915b536e4b36ef917c4e826a982dd47c312"
		or hash.sha256(0, filesize) == "8215e918ca3a77424dadac1aebc9a44b8f9840cd1389df0399a9fa4eb6329775"
		or hash.sha256(0, filesize) == "b8dc70b9ffe06c9ecaf0216ea7948fe718143db10641a23297652693ea026ab3"
		or hash.sha256(0, filesize) == "f4e710f515249e8c08ae76284bfb280070e1fd2308e9d9321d92163dfc73be66"
}
// =====================================   AS-IS  ====================================
