# Content 

This directory contains Yara (https://github.com/VirusTotal/yara) rules associated with the Cuckoo Spear (APT10) campaign.

The following Yara rule can be run on memory dumps (shellcode is generally encrypted and encrypted shellcode cannot be identified through Yara rule due to change): 
* noopldr-dll.yar
* xml_shellcode_noopdoor.yar
