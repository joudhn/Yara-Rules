
rule Unknown_Malware {
    meta:
        description = "Yara rules for Unknown Malware"
        md5 = "3908C840C08D7621762262F2B734DB05"
        sha1 = "93D245826066B3EB4D2CB68F554FAC615FFCB8A4"
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
