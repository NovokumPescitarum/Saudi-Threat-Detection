// ===================================== GENERATED ====================================

import "hash"
rule MISP_EVENT_ed8a4949_bb6c_4f82_a865_83c37717aa9f_PART1 : generated
{
	meta:
		MISP_EVENT_INFO = "KSA-TI Tortoiseshell"
		MISP_EVENT_UUID = "ed8a4949-bb6c-4f82-a865-83c37717aa9f"
		MISP_ORIGIN = "Automatically generated from non-Yara attribute(s)"
	strings:
		$ = "naturalapplication.azurewebsites.net" ascii wide
		$ = "retaildemo.azurewebsites.net" ascii wide
		$ = "tubitak.azurewebsites.net" ascii wide
		$ = "rgbteller.azurewebsites.net" ascii wide
		$ = "wslwebui.azurewebsites.net" ascii wide
		$ = "plugplay.azurewebsites.net" ascii wide
		$ = "crossdwm.azurewebsites.net" ascii wide
		$ = "wdisystem.azurewebsites.net" ascii wide
		$ = "wslmenus.azurewebsites.net" ascii wide
		$ = "dnshnsdev.azurewebsites.net" ascii wide
		$ = "hpjumpsrv.azurewebsites.net" ascii wide
		$ = "storview.azurewebsites.net" ascii wide
		$ = "healthcomfsdpower.com" ascii wide
		$ = "visitfinancedentists.com" ascii wide
		$ = "kyrasey-f8hfexa5cqamh7fk.westeurope-01.azurewebsites.net" ascii wide
		$ = "greenyjsgfd.azurewebsites.net" ascii wide
		$ = "helptellerbls.azurewebsites.net" ascii wide
		$ = "timedrv.azurewebsites.net" ascii wide
		$ = "userwellgtfs.azurewebsites.net" ascii wide
		$ = "hecowime-aqdphyd4bbdef6es.westeurope-01.azurewebsites.net" ascii wide
		$ = "msmanagementgrp.com" ascii wide
		$ = "msmanagementgrpmedia.com" ascii wide
		$ = "lifespotify.com" ascii wide
		$ = "gamebarapp.azurewebsites.net" ascii wide
		$ = "gamebarappinformation.azurewebsites.net" ascii wide
		$ = "sahi-finance.com" ascii wide
		$ = "healthful-hub.com" ascii wide
		$ = "neumedicahealthcare.com" ascii wide
		$ = "optimumhealthcredit.com" ascii wide
		$ = "healthfullyrecipes.com" ascii wide
		$ = "refreshhealthandwellness.com" ascii wide
		$ = "healthvitalitycare.com" ascii wide
		$ = "aceofspadesmanagement.com" ascii wide
		$ = "glmediaagency.com" ascii wide
		$ = "digimediaskill.com" ascii wide
		$ = "healthyweightplan.com" ascii wide
		$ = "mens-health-online.com" ascii wide
		$ = "neexportfolio.com" ascii wide
		$ = "neexportfolio.azurewebsites.net" ascii wide
		$ = "neexportfolio.eastus.cloudapp.azure.com" ascii wide
		$ = "locat.sbs" ascii wide
		$ = "tiktok-u.sbs" ascii wide
		$ = "172.86.98.113" ascii wide
		$ = "185.66.68.213" ascii wide
		$ = "185.253.116.71" ascii wide
		$ = "185.253.116.242" ascii wide
		$ = "185.253.118.246" ascii wide
		$ = "94.126.227.20" ascii wide
		$ = "89.44.80.42" ascii wide
		$ = "91.193.16.187" ascii wide
		$ = "89.44.80.234" ascii wide
		$ = "89.44.80.61" ascii wide
		$ = "94.126.227.119" ascii wide
		$ = "89.44.80.86" ascii wide
		$ = "89.44.80.6" ascii wide
		$ = "185.253.116.99" ascii wide
		$ = "89.44.80.56" ascii wide
		$ = "95.174.68.199" ascii wide
		$ = "185.253.116.166" ascii wide
		$ = "139.84.202.187" ascii wide
		$ = "188.119.149.200" ascii wide
		$ = "85.208.86.140" ascii wide
		$ = "89.44.80.96" ascii wide
		$ = "185.253.116.81" ascii wide
		$ = "79.141.167.230" ascii wide
		$ = "95.85.235.9" ascii wide
		$ = "167.179.89.68" ascii wide
		$ = "89.44.80.168" ascii wide
		$ = "72.56.34.52" ascii wide
		$ = "https://oracle-challenge.s3.us-east-1.amazonaws.com/Front-Technical-Challenge.zip" ascii wide
	condition:
		hash.md5(0, filesize) == "cbaaf0900a13f28e380f49adecec932c"
		or hash.md5(0, filesize) == "1ea83e4e4592b01e4acab63eb867bee5"
		or hash.md5(0, filesize) == "366515822d5ac1cc500711ef57a2e32e"
		or hash.md5(0, filesize) == "cf449f1992c2819e62ac44a0b06ac2e7"
		or hash.md5(0, filesize) == "e95a4366686e3f786ea3c056fab5b0da"
		or hash.md5(0, filesize) == "de5af16a3757ef700b01dc34d67079ae"
		or hash.md5(0, filesize) == "be086789568441d0d7e4679aee51f566"
		or hash.md5(0, filesize) == "e259c5edf158aac4cfe14f77ddd0b196"
		or hash.md5(0, filesize) == "291ac3abe73c5158e59a437b75d5f0aa"
		or hash.md5(0, filesize) == "0962f56d7ec69f4f2a0162dcbe22116b"
		or hash.md5(0, filesize) == "795e053a990a1569ffdcb57f48f6d085"
		or any of them
}
// =====================================   AS-IS  ====================================
