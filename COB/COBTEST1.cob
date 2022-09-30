       IDENTIFICATION DIVISION.
       PROGRAM-ID.  COBTEST1.
      ******************************************************************
      *                                                                *
      ******      C O M P U W A R E   C O R P O R A T I O N       ******
      *                                                                *
      *  THIS CALLED PROGRAM IS THE COBOL DEMO PROGRAM USED FOR        *
      *  XPEDITER/TSO TRAINING SESSIONS.
      *  TEST                             *
      *                                                                *
      ******************************************************************
       ENVIRONMENT DIVISION.
       DATA DIVISION.
       WORKING-STORAGE SECTION.
        01  TDA.
          05 TCO       PIC S99 VALUE 11.
          05   T-PART2 PIC X(1) VALUE '1'.
          05   T-PART3 PIC X(1) VALUE '2'.

       LINKAGE SECTION.
       01  TESTDATA.
          05  SALES-AMOUNT     PIC 9(6)V99.
          05  COMM-TOTAL    PIC 9(5)V99   COMP-3.


       PROCEDURE DIVISION USING TESTDATA.
       0000-MAINLINE.
           DISPLAY TESTDATA.

           move 066000.00 to SALES-AMOUNT.
           move 03300.00 to COMM-TOTAL.
           CALL 'TESTSUB4' USING TDA.

           GOBACK.
       0000-MAINLINE-EXIT.