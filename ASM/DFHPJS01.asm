* ASSEMBLY CLASS WORKSHOP 1                                             00001000
* 5/19/98                                                               00002000
* TESTING ASSEMBLY INSTRUCTIONS                                         00003000
*                                                                       00004000
DFHPJS01 CSECT                                                          00010000
         PRINT DATA                                                     00020000
*                                                                       00021000
* DUPLICATION FACTORS                                                   00022000
*                                                                       00023000
FIELDA   DS CL6                           CHAR LENGTH 6                 00030000
         DS 6C                            DUP. FACTOR 6, LENGTH 1       00031000
FIELDB   DC CL3'A'                                                      00032000
         DC CL3'SMITH'                    TRUNCATION HERE               00033000
FIELDC   DC 2C'A'                                                       00034000
         DC 5CL2'AB'                      DUP 5, CHAR 2 LENGTH 2        00035000
FIELDD   DC C'AAB'                        CHAR, IMPLIED LENGTH 3        00036000
FIELDE   DS 4XL3                                                        00037000
         DC X'AB'                                                       00038000
FIELDF   DC XL2'12'                                                     00039000
FIELDG   DC XL2'123456'                   TRUNCATION HERE               00040000
*                                                                       00050000
* DECLARE BINARY                                                        00060000
*                                                                       00070000
FIELDH   DC B'101'                                                      00080000
         DC BL3'110001'                   BINARY LENGTH 3               00090000
         DC BL2'111001010011'                                           00100000
*                                                                       00110000
* DECLARE FULLWORDS AND HALFWORDS                                       00120000
*                                                                       00130000
FIELDH2  DS CL2                                                         00131001
FIELDI   DC F'12345'                      WILL START ON FULL WORD       00140000
FIELD2   DC F'+12345'                     BOUNDARY                      00141000
FIELDJ   DC F'+1'                                                       00160000
FIELDJ2  DC CL1'A'                                                      00170000
FIELDK   DC H'-60'                        WILL START ON 1/2 WORD        00180000
FIELDL   DC H'-11'                                                      00190000
*                                                                       00200000
* DECLARE PACKED FIELDS                                                 00210000
*                                                                       00220000
FIELDM   DC PL3'5'                                                      00230000
FIELDM2  DC PL3'-5'                                                     00240000
FIELDN   DS PL2                                                         00250000
         DC PL2'123456'                                                 00260000
         DC PL2'-123456'                                                00270000
*                                                                       00280000
* DECLARE ZONED  FIELDS                                                 00290000
*                                                                       00300000
FIELDO   DC ZL4'5'                        SIGN LEFT MOST 0-3 BITS       00310000
FIELDP   DC ZL4'+18645'                   TRUNCATED                     00320000
         DC ZL4'-183'                     SEE NEGATIVE SIGN             00330000
*                                                                       00340000
* DECLARE VALUE OF ADDRESSES                                            00350000
*                                                                       00360000
FIELDQ   DC A(FIELDL)                     ADDRESS OF FIELDL             00370000
         DC AL3(FIELDM)                   LENGTH 3, ADDRESS OF FIELDM   00380000
         DC AL2(FIELDM-FIELDF)            SUBTRACT ADDRESSES            00390000
         DC C'AB',XL3'C3C4',B'11000101'   STACKING HERE                 00400002
*                                                                       00410000
* STOP LOCATION COUNTER                                                 00420000
*                                                                       00430000
DATE     DS 0CL10                                                       00440000
MONTH    DS CL2                                                         00450000
         DC C'/'                                                        00460000
DAY      DS CL2                                                         00470000
         DC C'/'                                                        00480000
YEAR     DS CL4                                                         00490000
*                                                                       00500000
* INSTRUCTIONS TO CHECK OUT                                             00510000
*                                                                       00520000
         DC V(PAM)                                                      00530000
         DC F'123.45'                                                   00540000
         DC H'60.5'                                                     00550000
         END                                                            00560000