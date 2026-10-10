// ===================================== GENERATED ====================================

import "hash"
rule MISP_EVENT_c596153e_3179_4fd9_b904_c451599fee48_PART1 : generated
{
	meta:
		actor = "APT33 (Elfin / Peach Sandstorm)"
		attack_techniques = "T1003,T1003.001,T1003.002,T1003.004,T1003.005,T1003.006,T1005,T1007,T1010,T1012,T1016,T1018,T1020,T1021,T1021.001,T1021.002,T1021.003,T1021.004,T1027,T1027.005,T1027.009,T1027.010,T1027.011,T1033,T1036"
		MISP_EVENT_INFO = "KSA-TI APT33 (Elfin / Peach Sandstorm)"
		MISP_EVENT_UUID = "c596153e-3179-4fd9-b904-c451599fee48"
		MISP_ORIGIN = "Automatically generated from non-Yara attribute(s)"
	condition:
		hash.sha256(0, filesize) == "5798aefb07e12a942672a60c2be101dc26b01485616713e8be1f68b321747f2f"
		or hash.sha256(0, filesize) == "a67461a0c14fc1528ad83b9bd874f53b7616cfed99656442fb4d9cdd7d09e449"
		or hash.sha256(0, filesize) == "f2943f5e45befa52fb12748ca7171d30096e1d4fc3c365561497c618341299d5"
		or hash.sha256(0, filesize) == "87e2cf4aa266212aa8cf1b1c98ae905c7bac40a6fc21b8e821ffe88cf9234586"
		or hash.sha256(0, filesize) == "709df1bbd0a5b15e8f205b2854204e8caf63f78203e3b595e0e66c918ec23951"
		or hash.sha256(0, filesize) == "a23c182349f17398076360b2cb72e81e5e23589351d3a6af59a27e1d552e1ec0"
		or hash.sha256(0, filesize) == "0b3610524ff6f67c59281dbf4a24a6e8753b965c15742c8a98c11ad9171e783d"
		or hash.sha256(0, filesize) == "d5262f1bc42d7d5d0ebedadd8ab90a88d562c7a90ff9b0aed1b3992ec073e2b0"
		or hash.sha256(0, filesize) == "ae1d75a5f87421953372e79c081e4b0a929f65841ed5ea0d380b6289e4a6b565"
		or hash.sha256(0, filesize) == "e999fdd6a0f5f8d1ca08cf2aef47f5ddc0ee75879c6f2c1ee23bc31fb0f26c70"
		or hash.sha256(0, filesize) == "018360b869d8080cf5bcca1a09eb8251558378eb6479d8d89b8c80a8e2fa328c"
		or hash.sha256(0, filesize) == "367e78852134ef488ecf6862e71f70a3b10653e642bda3df00dd012c4e130330"
		or hash.sha256(0, filesize) == "ea5295868a6aef6aac9e117ef128e9de107817cc69e75f0b20648940724880f3"
		or hash.sha256(0, filesize) == "6401abe9b6e90411dc48ffc863c40c9d9b073590a8014fe1b0e6c2ecab2f7e18"
		or hash.sha256(0, filesize) == "bf9c589de55f7496ff14187b1b5e068bd104396c23418a18954db61450d21bab"
		or hash.sha256(0, filesize) == "af41e9e058e0a5656f457ad4425a299481916b6cf5e443091c7a6b15ea5b3db3"
		or hash.sha256(0, filesize) == "c7a2559f0e134cafbfc27781acc51217127a7739c67c40135be44f23b3f9d77b"
		or hash.sha256(0, filesize) == "99c1228d15e9a7693d67c4cb173eaec61bdb3e3efdd41ee38b941e733c7104f8"
		or hash.sha256(0, filesize) == "94526e2d1aca581121bd79a699a3bf5e4d91a4f285c8ef5ab2ab6e9e44783997"
		or hash.sha256(0, filesize) == "dedfbc8acf1c7b49fb30af35eda5e23d3f7a202585a5efe82ea7c2a785a95f40"
}
// =====================================   AS-IS  ====================================
