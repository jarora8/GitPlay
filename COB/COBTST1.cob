       IDENTIFICATION DIVISIONN
       PROGRAM-ID.       COBTST1.
       AUTHOR           Test Program
       DATE-WRITTEN.     20 February 2017

      * A sample program just to show the form.
      * The program copies its input to the output,
      * and counts the number of records.
      * At the end this number is printed.

       ENVIRONMENT DIVISION.
       INPUT-OUTPUT SECTION.
       FILE-CONTROL.
           SELECT STUDENT-FILE     ASSIGN TO SYSIN
               ORGANIZATION IS LINE SEQUENTIAL.
           SELECT PRINT-FILE       ASSIGN TO SYSOUT
               ORGANIZATION IS LINE SEQUENTIAL.

       DATA DIVISION.
       FILE SECTION.
       FD  STUDENT-FILE
           RECORD CONTAINS 43 CHARACTERS
           DATA RECORD IS STUDENT-IN.
       01  STUDENT-IN              PIC X(43).

       FD  PRINT-FILE
           RECORD CONTAINS 80 CHARACTERS
           DATA RECORD IS PRINT-LINE.
       01  PRINT-LINE              PIC X(80).

       WORKING-STORAGE SECTION.
       01  DATA-REMAINS-SWITCH     PIC X(2)      VALUE SPACES.
       01  RECORDS-WRITTEN         PIC 99.

       01  DETAIL-LINE.
           05  FILLER              PIC X(7)      VALUE SPACES.
           05  RECORD-IMAGE        PIC X(43).
           05  FILLER              PIC X(30)     VALUE SPACES.

       01  SUMMARY-LINE.
           05  FILLER              PIC X(7)      VALUE SPACES.
           05  TOTAL-READ          PIC 99.
           05  FILLER              PIC X         VALUE SPACE.
           05  FILLER              PIC X(17)
                       VALUE  'Records were read'.
           05  FILLER              PIC X(53)     VALUE SPACES.

       PROCEDURE DIVISION.

       PREPARE-SENIOR-REPORT.
           OPEN INPUT  STUDENT-FILE
                OUTPUT PRINT-FILE.
           MOVE ZERO TO RECORDS-WRITTEN.
           READ STUDENT-FILE
               AT END MOVE 'NO' TO DATA-REMAINS-SWITCH
           END-READ.
           PERFORM PROCESS-RECORDS
               UNTIL DATA-REMAINS-SWITCH = 'NO'.
           PERFORM PRINT-SUMMARY.
           CLOSE STUDENT-FILE
                 PRINT-FILE.
           STOP RUN.

       PROCESS-RECORDS.
           MOVE STUDENT-IN TO RECORD-IMAGE.
           MOVE DETAIL-LINE TO PRINT-LINE.
           WRITE PRINT-LINE.
           ADD 1 TO RECORDS-WRITTEN.
           READ STUDENT-FILE
               AT END MOVE 'NO' TO DATA-REMAINS-SWITCH
           END-READ.

       PRINT-SUMMARY.
           MOVE RECORDS-WRITTEN TO TOTAL-READ.
           MOVE SUMMARY-LINE TO PRINT-LINE.
           WRITE PRINT-LINE.