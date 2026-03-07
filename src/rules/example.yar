// ECOBIO Antivirus — Example Rule
// This file demonstrates the rule format used by ECOBIO detection engine.
// Production rules are maintained separately and distributed via ecobio-av update feed.

rule ECOBIO_Example_Suspicious_Script {
    meta:
        author = "ECOBIO Security"
        description = "Example: detects a test string used for scanner validation"
        threat_level = "low"
        mitre = "T1059 - Command and Scripting Interpreter"
        action = "ALERT"

    strings:
        $test = "ECOBIO-TEST-DETECTION" ascii wide

    condition:
        $test
}

rule ECOBIO_Example_EICAR {
    meta:
        author = "ECOBIO Security"
        description = "Standard EICAR antivirus test file detection"
        threat_level = "low"
        mitre = "N/A - Test file"
        action = "ALERT"

    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    condition:
        $eicar at 0
}
