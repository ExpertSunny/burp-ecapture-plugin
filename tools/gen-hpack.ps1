# Generates src/main/java/com/ecapture/burp/h2/HpackTables.java
# from the RFC 7541 text file (Appendix A static table + Appendix B Huffman code).
param(
    [Parameter(Mandatory = $true)][string]$RfcText,
    [Parameter(Mandatory = $true)][string]$OutFile
)

$lines = Get-Content -Path $RfcText

# ---- Appendix A: static table -------------------------------------------------
$static = New-Object System.Collections.Generic.List[string]
$inStaticTable = $false
$staticCount = 0
foreach ($l in $lines) {
    if ($l -match 'Table 1: Static Table Entries') { break }
    if ($l -match '^\s+\|\s*Index\s*\|') { $inStaticTable = $true; continue }
    if ($inStaticTable) {
        if ($l -match '^\s+\|\s*(\d+)\s*\|\s*([^|]*?)\s*\|\s*([^|]*?)\s*\|') {
            $i = [int]$Matches[1]
            $name = $Matches[2].Trim()
            $val = $Matches[3].Trim()
            if ($i -ne $staticCount + 1) { throw "static table index gap: $i after $($staticCount)" }
            $staticCount++
            $static.Add("        {`"$name`", `"$val`"}")
        }
    }
}
if ($staticCount -ne 61) { throw "expected 61 static entries, got $staticCount" }

# ---- Appendix B: Huffman codes ------------------------------------------------
$huff = New-Object System.Collections.Generic.List[string]
$inHuff = $false
$huffCount = 0
foreach ($l in $lines) {
    if ($l -match 'Appendix C\.  Examples') { break }
    if ($l -match 'Appendix B\.  Huffman Code') { $inHuff = $true; continue }
    if ($inHuff) {
        if ($l -match '\(\s*(\d+)\)\s+\|[^\[]*?([0-9a-f]+)\s+\[\s*(\d+)\s*\]') {
            $sym = [int]$Matches[1]
            $hex = $Matches[2]
            $len = [int]$Matches[3]
            if ($sym -ne $huffCount) { throw "huffman sym gap: $sym after $($huffCount)" }
            $huffCount++
            $huff.Add("        { 0x$hex, $len } // sym $sym")
            if ([System.Numerics.BigInteger]::Parse($hex, [System.Globalization.NumberStyles]::AllowHexSpecifier) -ge ([math]::Pow(2, $len))) { throw "code too long for $sym" }
        }
    }
}
if ($huffCount -ne 257) { throw "expected 257 huffman entries, got $huffCount" }

$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine('// Generated from RFC 7541 Appendix A (static table) and Appendix B')
[void]$sb.AppendLine('// (Huffman code) by tools/gen-hpack.ps1. Do not edit by hand.')
[void]$sb.AppendLine('package com.ecapture.burp.h2;')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('final class HpackTables {')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('    static final String[][] STATIC_TABLE = {')
for ($i = 0; $i -lt $static.Count; $i++) {
    $comma = if ($i -lt $static.Count - 1) { ',' } else { '' }
    [void]$sb.AppendLine("$($static[$i])$comma")
}
[void]$sb.AppendLine('    };')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('    /** {code, bitLength} indexed by symbol 0..256 (256 = EOS). */')
[void]$sb.AppendLine('    static final int[][] HUFFMAN_CODES = {')
for ($i = 0; $i -lt $huff.Count; $i++) {
    $comma = if ($i -lt $huff.Count - 1) { ',' } else { '' }
    $entry = $huff[$i].Replace(' } // sym', ' }' + $comma + ' // sym')
    [void]$sb.AppendLine($entry)
}
[void]$sb.AppendLine('    };')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('    private HpackTables() {')
[void]$sb.AppendLine('    }')
[void]$sb.AppendLine('}')

Write-Output $sb.ToString() | Set-Content -Path $OutFile -Encoding UTF8
Write-Host "Generated $OutFile with $staticCount static entries and $huffCount huffman codes"
