rule xml_shellcode {
   meta:
      description = "NOOPDOOR shellcode"
      author = "Jin Ito"
      date = "2023-12-13"
   strings:
      $s1 = "E(.dll" fullword ascii
      $s2 = "E8.dllL" fullword ascii
      $s3 = "D$puser" fullword ascii
      $s4 = "D$Dl.dlf" fullword ascii
      $s5 = "D$42.dlf" fullword ascii
      $s6 = "D$$2.dlf" fullword ascii
      $s7 = "t;fffffff" fullword ascii /* Goodware String - occured 1 times */
      $s8 = "f;\\$`u" fullword ascii /* Goodware String - occured 3 times */
      $s9 = "D$Pws2_" fullword ascii
      $s10 = " A]A\\_" fullword ascii
      $s11 = "E adva" fullword ascii
      $s12 = "E0olea" fullword ascii
      $s13 = "D$(thre" fullword ascii
      $s14 = "D$0ole3" fullword ascii
      $s15 = "u>IcD$" fullword ascii
      $s16 = "D$xllH" fullword ascii
      $s17 = "udHcK<" fullword ascii
      $s18 = "D$T32.df" fullword ascii
      $s19 = "D$lle n" fullword ascii
      $s20 = "L$(D+MoD" fullword ascii
   condition:
      ( 8 of them )
}

