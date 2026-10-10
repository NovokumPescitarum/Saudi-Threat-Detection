// ===================================== GENERATED ====================================


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
		any of them
}
// =====================================   AS-IS  ====================================
