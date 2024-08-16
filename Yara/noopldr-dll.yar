rule _NOOPLDR-DLL{
   meta:
      description = "NOOPLDR-DLL detection"
      author = "Cybereason"
      date = "2024-02-01"
   strings:
      $s1 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s2 = "UAWAVAUATVWS" fullword ascii
      $s3 = "UAWAVVWSH" fullword ascii
      $s4 = "AWAVAUATVWUSH" fullword ascii
      $s5 = "UAWAVAUATVWSH" fullword ascii
      $s6 = "UAWAVATVWSH" fullword ascii
      $s7 = "UAVVWSH" fullword ascii
      $s8 = "AWAVVWUSH" fullword ascii
      $s9 = "AVVWUSH" fullword ascii
      $s10 = "  </trustInfo>" fullword ascii
      $s11 = "      <requestedPrivileges>" fullword ascii
      $s12 = "      </requestedPrivileges>" fullword ascii
      $s13 = " [_^A^]" fullword ascii
      $s14 = "h[]_^A\\A]A^A_" fullword ascii
      $s15 = "8[_^A\\A]A^A_]" fullword ascii
      $s16 = "`[_^A^]" fullword ascii
      $s17 = "[_^A\\A]A^A_]" fullword ascii
      $s18 = "[]_^A\\A]A^A_" fullword ascii
      $s19 = "X[]_^A\\A]A^A_" fullword ascii
      $s20 = "h[_^A\\A]A^A_]" fullword ascii
   condition:
      (  uint16(0) == 0x5a4d and filesize < 1000KB and ( 20 of them ) ) or ( all of them )
}

