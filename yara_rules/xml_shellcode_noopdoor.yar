rule xml_shellcode {
   meta:
      description = "NOOPDOOR shellcode"
      author = "Cybereason"
      date = "2023-12-13"
   strings:
      $s1 = "E(.dll" fullword ascii
      $s2 = "E8.dllL" fullword ascii
      $s3 = "D$puser" fullword ascii
      $s4 = "D$Dl.dlf" fullword ascii
      $s5 = "D$42.dlf" fullword ascii
      $s6 = "D$$2.dlf" fullword ascii
      $s7 = "D$Pws2_" fullword ascii
      $s8 = " A]A\\_" fullword ascii
      $s9 = "E adva" fullword ascii
      $s10 = "E0olea" fullword ascii
      $s11 = "D$(thre" fullword ascii
      $s12 = "D$0ole3" fullword ascii
      $s13 = "u>IcD$" fullword ascii
      $s14 = "D$xllH" fullword ascii
      $s15 = "udHcK<" fullword ascii
      $s16 = "D$T32.df" fullword ascii
      $s17 = "D$lle n" fullword ascii
      $s18 = "L$(D+MoD" fullword ascii
   condition:
      ( 8 of them )
}

