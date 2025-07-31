rule Ransomware_Indicator {
    meta:
        description = "Detects common ransomware strings"
        author = "Marc Brocato"
    strings:
        $s1 = "ransom" ascii wide
        $s2 = ".encrypted" ascii
    condition:
        any of them
}

rule APT_Actor {
    meta:
        description = "Detects APT-related domains"
        author = "Marc Brocato"
    strings:
        $d1 = "aptgroup.domain" ascii
    condition:
        $d1
}
