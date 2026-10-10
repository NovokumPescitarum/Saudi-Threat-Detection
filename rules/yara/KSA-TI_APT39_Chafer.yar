// ===================================== GENERATED ====================================

import "hash"
rule MISP_EVENT_c743fd85_b859_43e7_9378_de83a07a9618_PART1 : generated
{
	meta:
		MISP_EVENT_INFO = "KSA-TI APT39/Chafer"
		MISP_EVENT_UUID = "c743fd85-b859-43e7-9378-de83a07a9618"
		MISP_ORIGIN = "Automatically generated from non-Yara attribute(s)"
	condition:
		hash.sha256(0, filesize) == "94cae63dcbabb71c5dd43f55fd09caeffdcd7628a02a112fb3cba36698ef72bc"
		or hash.sha256(0, filesize) == "fb9e181d3ea6faa9d0e7431bfc8301fd66bcc8c3d66b26cef7036d117ee5fbb1"
		or hash.sha256(0, filesize) == "a1672417b70e407cec5d81446b6c197e169909edddae925d18b183828d3450ed"
		or hash.sha256(0, filesize) == "863db5a8b6564e44b5dbfef8da2e62cde00e32b03c29321628fc30d67f1eb891"
		or hash.sha256(0, filesize) == "2555e848eda2a5a9bc48d107520b7fb3faf684ce45b12d763981655aecd3f057"
		or hash.sha256(0, filesize) == "3fc3ecfd634344c11abb594c3ecb9f05cea3117607bda0a129115cb87dd9b3fa"
		or hash.sha256(0, filesize) == "e1796b1b2cc3b32fb7c81c61b6ed7ae7e5a7a247d2d7f323cf54c3583fe89990"
		or hash.sha256(0, filesize) == "6085b743a677204f6c8263b3c9baf50c588c48fab7dfa1d0fa87a89b47a67d08"
		or hash.sha256(0, filesize) == "caf0b9afe8f3cb2037640a49d3aaec078940b6ea193338bb5a482e5d2f5fd21c"
		or hash.sha256(0, filesize) == "7eb05334bb1fa0cb49b095a906821bccdbab94348613919fdeb1ee60ef1346b7"
		or hash.sha256(0, filesize) == "da6b03ee40f03e27547c2f92df3e22222c14e56e182e2b0c71828eb06f837eb8"
		or hash.sha256(0, filesize) == "4c5de55447be1a635ddfbf405ad4927b6d75ef42949559b083b314f0fcc19423"
		or hash.sha256(0, filesize) == "c839e886b98d2c752a134e888dad40799cd9966f8a73b51edc85ca2d72f99616"
		or hash.sha256(0, filesize) == "cbcc37f37d326d3c3def52b3e3a42d14857d56ba6b6e13d02b3cd041cbb2aa3a"
		or hash.sha256(0, filesize) == "3d1d3871edd985cae2838f4b7fbae6675d70e28bb8606ac42b5b7591290f0e96"
		or hash.sha256(0, filesize) == "29fe8ea77382e942bcb318c54ba98c3b33db48240591cc0b6ca61860a8070d01"
		or hash.sha256(0, filesize) == "3b826c09907aa099098bdafa876381c21dd72691ef3f26f1a5cb99795c7da067"
		or hash.sha256(0, filesize) == "29b24268c57e306e6ba881f80998188dc1e76e64621535380e4b67e8d086f658"
		or hash.sha256(0, filesize) == "06b15c48ba3bda15a38ab840538ea919f6a721361c590956a7b389fdafefcabd"
		or hash.sha256(0, filesize) == "ade900cf62545fa8b56c15132fc4d5ffc5e160b08aa5679f5e438c154aed02b0"
		or hash.sha256(0, filesize) == "8a4bc150868f870e05acb743b6798109aa302712c7e971ba6c61553e28fa0bcd"
		or hash.sha256(0, filesize) == "39daa8fe6a9f017dcdfe911b48031d8d20218da589e3d7608066aa1aa18b0d5b"
}
// =====================================   AS-IS  ====================================
