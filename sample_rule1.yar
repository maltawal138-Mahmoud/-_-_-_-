rule Student_Sample_Detection
{
    meta:
        author = "Mahmoud Altawal"
        description = "Detects the analyzed Go malware training sample"
        date = "2026-08-12"
        hash_md5 = "1aff346c3aedcf9cbff9fab0cb8a65c3"
        hash_sha256 = "728dc58f77ea10cd6b1fa5407ead6a8b93c3b38ea45549c2cfa1e6c8de74ad84"

    strings:
        // Unique Go Build ID extracted from Strings analysis
        $go_build_id = "3wRIgTbQ1iOPwp1p4o7C/GU4fCqqRrOuh9DiFGvYI/wtXTeb3arGcAnnIym2WV/BKHnKQ3gEl-slcY6Ksce" ascii
        
        // ROT13 obfuscated path found in Registry (Regshot)
        $rot13_path = "P:\\Hfref\\" ascii wide
        
        // Standard DOS stub string
        $dos_stub = "This program cannot be run in DOS mode." ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 6MB and
        $go_build_id
}