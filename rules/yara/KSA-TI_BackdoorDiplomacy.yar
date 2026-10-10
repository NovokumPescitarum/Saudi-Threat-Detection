// ===================================== GENERATED ====================================

import "hash"
rule MISP_EVENT_0ae43b70_f656_4452_aab9_7070f18e50ff_PART1 : generated
{
	meta:
		MISP_EVENT_INFO = "KSA-TI BackdoorDiplomacy"
		MISP_EVENT_UUID = "0ae43b70-f656-4452-aab9-7070f18e50ff"
		MISP_ORIGIN = "Automatically generated from non-Yara attribute(s)"
	condition:
		hash.sha1(0, filesize) == "3c0db3a5194e1568e8e2164149f30763b7f3043d"
		or hash.sha1(0, filesize) == "32ef3f67e06c43c18e34fb56e6e62a6534d1d694"
		or hash.sha1(0, filesize) == "8c4d2ed23958919fe10334ccfbe8d78cd0d991a8"
		or hash.sha1(0, filesize) == "c0a3f78cf7f0b592ef813b15fc0f1d28d94c9604"
		or hash.sha1(0, filesize) == "cdd583bb6333644472733617b6dcee2681238a11"
		or hash.sha1(0, filesize) == "fa6c20f00f3c57643f312e84cc7e46a0c7babe75"
		or hash.sha1(0, filesize) == "5f87fbfe30ca5d6347f4462d02685b6e1e90e464"
		or hash.sha1(0, filesize) == "b6936bd6f36a48dd1460eeb4ab8473c7626142ac"
		or hash.sha1(0, filesize) == "b16393dffb130304ad627e6872403c67dd4c0af3"
		or hash.sha1(0, filesize) == "9dbbebebba20b1014830b9de4ec9331e66a159df"
		or hash.sha1(0, filesize) == "564f1c32f2a2501c3c7b51a13a08969cdc3b0390"
		or hash.sha1(0, filesize) == "6e1bb476ee964fff26a86e4966d7b82e7bacbf47"
		or hash.sha1(0, filesize) == "fbb0a4f4c90b513c4e51f0d0903c525360faf3b7"
		or hash.sha1(0, filesize) == "2183ae45adef97500a26dbbf69d910b82bfe721a"
		or hash.sha1(0, filesize) == "849b970652678748cebf3c4d90f435ae1680601f"
		or hash.sha1(0, filesize) == "c176f36a7fc273c9c98ea74a34b8bab0f490e19e"
		or hash.sha1(0, filesize) == "626efb29b0c58461d831858825765c05e1098786"
		or hash.sha1(0, filesize) == "40e73bf21e31ee99b910809b3b4715af017db061"
		or hash.sha1(0, filesize) == "255f54de241a3d12debad2df47bac5601895e458"
		or hash.sha1(0, filesize) == "a99cf07fba62a63a44c6d5ef6b780411cf1b1073"
		or hash.sha1(0, filesize) == "934b3934fdb4cd55dc4ea1577f9a394e9d74d660"
		or hash.sha1(0, filesize) == "ef4df176916ce5882f88059011072755e1ecc482"
}
// =====================================   AS-IS  ====================================
