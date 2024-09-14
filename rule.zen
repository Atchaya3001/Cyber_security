rule MaliciousCProgram
{
    meta:
        description = "Detects a sample malicious C program"
        author = "Your Name"
        date = "2024-08-27"
    
    strings:
        $a = "This is a malicious C program."
        $b = "system("
        $c = "Malicious activity detected!"
    
    condition:
        any of ($a, $b, $c)
}
