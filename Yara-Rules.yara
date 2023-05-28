
rule Unknown_Malware {
    meta:
        description = "Yara rules for Unknown Malware"
        md5 = "6147b3df04d5d93d9186f3ede6e74b71"
        sha1 = "28781551d4b8fc8700672fe2320945b56155aff2"
        filename = "Unknown_Malware.exe"
        author = "Joud Hannoun and Maryam Nassar"
    strings:
        $pe = "MZ"
        $b = "PSUT.dll is missing!" wide
        $c = "C:\\windows\\updator.exe" wide
        $d= "CaesarCipher" ascii
        $e ="C:\\Users\\Hacked.txt"wide
        $f= "http://www.example.com/post_handler" wide
        $g ="SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = True" wide
    condition:
        ($pe at 0 and ($b or $c)) or ( ($pe at 0 and ($d and $e)) or ($f or $g) )
}
