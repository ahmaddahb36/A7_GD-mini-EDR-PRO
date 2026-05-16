
rule test_rule {
    strings:
        $a = "powershell"
    condition:
        $a
}
