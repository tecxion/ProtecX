/*
 * Reglas mínimas incluidas con ProtecX para funcionar sin conexión.
 * El grueso de la detección viene de las reglas descargadas con `protecx update`.
 * El campo `score` (0-100) determina la gravedad del hallazgo.
 */

rule EICAR_Test_File
{
    meta:
        description = "Fichero de prueba estándar EICAR (inofensivo)"
        score = 100
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Mimikatz_Strings
{
    meta:
        description = "Cadenas características de Mimikatz (robo de credenciales)"
        score = 85
    strings:
        $a = "sekurlsa::logonpasswords" ascii wide nocase
        $b = "gentilkiwi" ascii wide
        $c = "mimikatz" ascii wide nocase
    condition:
        2 of them
}

rule Webshell_PHP_Generic
{
    meta:
        description = "Webshell PHP genérica (eval/system sobre entrada del usuario)"
        score = 80
    strings:
        $obf = /eval\s*\(\s*(base64_decode|gzinflate|str_rot13)\s*\(/ nocase
        $exec = /(eval|assert|system|passthru|shell_exec)\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/ nocase
    condition:
        any of them and filesize < 200KB
}

rule Reverse_Shell_Script
{
    meta:
        description = "Script con reverse shell de bash"
        score = 80
    strings:
        $a = "bash -i" ascii
        $b = "/dev/tcp/" ascii
    condition:
        all of them and filesize < 100KB
}

rule Crypto_Miner_Config
{
    meta:
        description = "Configuración o binario de minero de criptomonedas"
        score = 65
    strings:
        $a = "stratum+tcp://" ascii
        $b = "donate-level" ascii
        $c = "xmrig" ascii nocase
    condition:
        2 of them
}
