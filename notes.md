mach-o decryption dumper
DISCLAIMER: This tool is only meant for security research purposes, not for application crackers.
[+] detected 32bit ARM binary in memory.
[+] offset to cryptid found: @0x1ba08(from 0x1b000) = a08
[+] Found encrypted data at address 00004000 of length 573440 bytes - type 1.
[+] Opening /private/var/mobile/Containers/Bundle/Application/A9622900-FC0A-4D64-AC2E-AC9B69773A22/xxx.app/PlugIns/xxx.appex/xxx for reading.
[+] Reading header
[+] Detecting header type
[+] Executable is a FAT image - searching for right architecture
[+] Correct arch is at offset 16384 in the file
[+] Opening /var/mobile/Containers/Data/PluginKitPlugin/D5C1CB12-DB5B-4C53-9191-B23142841035/Documents/xxx.decrypted for writing.
[+] Copying the not encrypted start of the file
[+] Dumping the decrypted data into the file
[+] Copying the not encrypted remainder of the file
[+] Setting the LC_ENCRYPTION_INFO->cryptid to 0 at offset 4a08
[+] Closing original file
[+] Closing dump file