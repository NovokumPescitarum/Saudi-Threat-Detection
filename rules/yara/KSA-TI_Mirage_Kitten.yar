// ===================================== GENERATED ====================================

import "hash"
rule MISP_EVENT_71712d0d_8199_4cf8_a24a_dda398fc6967_PART1 : generated
{
	meta:
		MISP_EVENT_INFO = "KSA-TI Mirage Kitten"
		MISP_EVENT_UUID = "71712d0d-8199-4cf8-a24a-dda398fc6967"
		MISP_ORIGIN = "Automatically generated from non-Yara attribute(s)"
	condition:
		hash.md5(0, filesize) == "de5af16a3757ef700b01dc34d67079ae"
		or hash.md5(0, filesize) == "e259c5edf158aac4cfe14f77ddd0b196"
		or hash.md5(0, filesize) == "810f8e3b88eb05f710c09552941d6f56"
		or hash.md5(0, filesize) == "be086789568441d0d7e4679aee51f566"
		or hash.md5(0, filesize) == "cbaaf0900a13f28e380f49adecec932c"
		or hash.md5(0, filesize) == "1ea83e4e4592b01e4acab63eb867bee5"
		or hash.md5(0, filesize) == "291ac3abe73c5158e59a437b75d5f0aa"
		or hash.md5(0, filesize) == "366515822d5ac1cc500711ef57a2e32e"
		or hash.md5(0, filesize) == "cf449f1992c2819e62ac44a0b06ac2e7"
		or hash.md5(0, filesize) == "0962f56d7ec69f4f2a0162dcbe22116b"
		or hash.md5(0, filesize) == "e95a4366686e3f786ea3c056fab5b0da"
		or hash.md5(0, filesize) == "795e053a990a1569ffdcb57f48f6d085"
}
// =====================================   AS-IS  ====================================
