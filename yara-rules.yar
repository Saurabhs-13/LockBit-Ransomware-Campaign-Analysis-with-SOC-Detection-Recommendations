rule lockbit_ransomware
{
    meta:
        description = "Detect LockBit ransomware behavior"

    strings:
        $s1 = "Restore-My-Files.txt"
        $s2 = "LockBit"

    condition:
        any of them
}