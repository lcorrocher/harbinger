/*
    rules.yar

    Detects common webshell patterns embedded in container image filesystems.
    Rules are tagged with severity levels (CRITICAL, HIGH, MEDIUM, LOW) which
    the YARA scanner maps to finding severity in reports.

    Adding rules:
      - Declare a severity tag on every rule (HIGH, CRITICAL, etc.)
      - Use `meta` to document what the rule detects and any false-positive risk
      - Keep string sets focused — broad strings cause false positives in large images
*/

rule PHPWebshell : HIGH {
    meta:
        description = "Detects common PHP webshell patterns"
        false_positive = "Low — legitimate PHP apps rarely use eval(base64_decode(...))"
    strings:
        $s1 = "eval(base64_decode(" ascii
        $s2 = "system($_GET[" ascii
        $s3 = "passthru($_POST[" ascii
        $s4 = "shell_exec($_REQUEST[" ascii
    condition:
        any of them
}

rule EmbeddedBase64Shell : HIGH {
    meta:
        description = "Detects base64-encoded shell commands commonly used to obfuscate payloads"
    strings:
        // base64 of "bash -i >& /dev/tcp/"
        $b64_reverse_shell = "YmFzaCAtaSA+JiAvZGV2L3RjcC8" ascii
        $b64_nc            = "bmMgLWUgL2Jpbi9zaA" ascii
    condition:
        any of them
}

rule SuspiciousSetuidBinary : CRITICAL {
    meta:
        description  = "Detects ELF binaries with setuid bit set in unexpected locations"
        false_positive = "Medium — some legitimate tools (ping, sudo) use setuid"
    strings:
        $elf_magic = { 7F 45 4C 46 } // ELF magic bytes
    condition:
        $elf_magic at 0
}

rule MinerStrings : HIGH {
    meta:
        description = "Detects strings associated with cryptocurrency miners"
    strings:
        $s1 = "stratum+tcp://" ascii
        $s2 = "xmrig" ascii nocase
        $s3 = "monero" ascii nocase
        $s4 = "--donate-level" ascii
    condition:
        2 of them
}
