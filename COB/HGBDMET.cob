       IDENTIFICATION DIVISION.
       PROGRAM-ID.  'HGBDMET'.

      *-- NOTE: This program is a stub for testing moving of data
      *         between the Topaz desktop client and the eventual
      *         actual HGADMET Hogan adapter program to be supplied by
      *         DXC. Program HOGANRUN calls this program as a
      *         "target" to do this. Data is moved between Topaz
      *         and the mainframe using files BININ and BINOUT.

      *         This version of the program uses what are expected to
      *         the actual, final data structures for its parameters.

       ENVIRONMENT DIVISION.

       DATA DIVISION.

       WORKING-STORAGE SECTION.
       77 w-RC                             pic S9(4) comp value ZERO.

       LINKAGE SECTION.
       copy A49211D.
       copy A49212D.
       copy A49214D.
       copy A49213D replacing leading ==A213== by ==I213==.
       copy A49213D replacing leading ==A213== by ==O213==.

      *=================================================================
      * Call to retrieve metadata...
      *=================================================================
      * INPUT FIELDS
      *-----------------------------------------------------------------
      *   849211_API_TRAN: 'AUMTOPAZ'
      *   849211_UserID: server side user ID; only required for
      *                  849212_FPSTrace_Request.
      *   Initial implementation will only support 849212_Map_Request.
      *   894211_Server: IMS or CICS subsystem on which the request
      *                  will be processed.
      *-----------------------------------------------------------------
      *   849212-Input-Map: name of map for input (specify "NONE" for
      *                     entry from a blank, cleared 3270 screen).
      *   849212-Response-Map: name of the output map.
      *-----------------------------------------------------------------
      *   I213-Description: contains a description of the input map's
      *                     function.
      *   I213-Copybook: contains a COBOL copybook mapping all the
      *                  fields in the input map. There are TWO fields
      *                  for each map field, the first is a one-byte
      *                  attribute field, which is followed by the
      *                  actual map field.
      *   I213-RDW: is a standard z/OS record descriptor word, so the
      *             number of entries in I213-Copybook is
      *             (I213-RDW - 4) / 80.
      *=================================================================
      * OUTPUT FIELDS
      *-----------------------------------------------------------------
      *   849211_Message_Number: zero if request was successful;
      *                          otherwise, the request failed.
      *   849211_Message_Text: error message text.
      *-----------------------------------------------------------------
      *   O213-Description: contains a description of the output map's
      *                     function.
      *   O213-Copybook: contains a COBOL copybook mapping for the
      *                  fields on the output map. For consistency,
      *                  this has the same two-field layout as for the
      *                  input map copybook, however the attribute
      *                  field is not used on output operations.
      *   O213-RDW: is a standard z/OS record descriptor word, so the
      *             number of entries in I213-Copybook is
      *             (O213-RDW - 4) / 80.
      *-----------------------------------------------------------------
      *   The entirety of A49214D-Run-Time-MetaData should be saved by
      *   Topaz from the call to retrieve metadata and passed back in
      *   when the actual application transaction is executed. A214-RDW
      *   is a standard z/OS record descriptor word, so the length of
      *   A49214D-Run-Time-MetaData is A214-RDW-Length.
      *=================================================================

       PROCEDURE DIVISION USING 849211_API_TRAN
                                849211_UserID
                                894211_Server
                                849211_Message
                                849212-MetaData_Request h
                                A49214D-Run-Time-MetaDataꞸ
                                I213-Map-Fields-Copybook
                                O213-Map-Fields-Copybook.

           display 'Transaction ID:  '      849211_API_TRAN
           display 'User ID: '              849211_UserID
           display 'Server: '               894211_Server
           move 'TransactionLabel, if possible'
               to l-transLabel
           move 'Longer Transaction Description, if possible'
               to l-transDescription
           move LOW-VALUES to l-returnXml
           string
               '<?xml version="1.0" encoding="UTF-8"?>'
               '<metadata>'
                 '<hoganfield name="FieldA">'
                   '<properties:properties>'
                   '<properties:property name="displayLength" '
                       'type="number">4</properties:property>'
                   '<properties:property name="platform" '
                       'type="string">mainframe</properties:property>'
                   '<properties:property name="storageLength" '
                       'type="number">4</properties:property>'
                   '</properties:properties>'
                 '</hoganfield>'
               '</metadata>'
               delimited by size into l-returnXml
           move ZERO to l-returnXmlSize
           inspect l-returnXml tallying l-returnXmlSize for characters
               before initial LOW-VALUE.
           move w-RC to RETURN-CODE

           GOBACK.