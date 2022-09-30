/*Copyright (c) 2014 Compuware Corporation, All Rights Reserved.*/
//  Copyright 2014-2019, 2020 BMC Software, Inc.

/* File-AIE Mainframe Modernization Project

/*------------------------------------------------------------------*/
/*                                                                  */
/* XFRRSRVR: This is a server routine to offer RDX relationship     */
/*      services to the Compuware Workbench, via HCI.               */
/*                                                                  */
//-------------------------------------------------------------------
//  HISTORY
//  -------
//  yyyy/mm/dd  who change ID  comment
//  ----------  --- ---------  ---------------------------
//  2014/04/30  ejk D0014414   new
//  2014/09/03  EJK misc       Trace data
//  2014/09/04  EJK misc       abend reporting problem
//  2014/09/22  EJK D0017091   trace test
//  2014/09/26  EJK D0016408   Use RDXMLIB
//  2014/10/07  EJK D0017439   Must call RDXGSU earlier
//  2014/10/08  EJK D0017216   test for CEASE/DISCONNECT
//  2014/10/09  EJK D0017425   abend reporting-get it right
//  2014/10/24  EJK D0017216   tracing for CEASE/Disconnect
//  2014/10/27  EJK misc       tracing for creator list
//  2014/10/29  EJK  misc1     more tracing for creator list
//  2014/10/31  EJK D0017216-2 WTO for CEASE/Disc/ABEND
//  2014/10/31  EJK D0017764   abend reporting
//  2016/10/24  EJK CWE101556  CWE101556 - connect to DB2
//  2016/10/25  EJK CWE101609  CWE101609 PROCRELS trans
//  2016/11/03      CWE101609A  Part of above, clean up.
//  2016/11/11  EJK CWE103449  add LOADRIRELS transaction
//  2016/11/28  EJK CWE104034  adj for LOADRIRELS
//  2016/12/02  EJK CWE103802  allocate RDXMLIB
//  2017/02/22  MJR CWE107575  Correcting improper use of error codes
//  2018/08/17  tjs cwe134588  use DD XFRXTRC for batch tracing when
//                             the FRTRACE tag is y in the INIT req
//  2018/09/19  YXT CWE137442  Add stub code for EXECREQ transaction
//  2018/09/20  tjs cwe137985  Add call to XFRXENCD() for EXECREQ trans
//  2018/09/20  tjs cwe138369  Call XFRPOPUL() to allocate/populate datasets
//  2018/10/08  tjs cwe138631  add call to xfrm2ds()
//  2018/10/24  tjs cwe139432  implement trace file handling properly
//  2018/10/31  tjs cwe139616  handle new tags for javainfo overrides
//  2018/11/07  tjs cwe139919  handle invalid HLQ; don't return multiblock
//  2018/11/16  mpd CWE119900/ Invalid Jobid in response from Topaz
//                  CWE140500  execution.
//  2018/11/16  mpd CWE139235/ Return extract or load error printed on
//                  CWE141343  ESR report to Topaz.
//  2019/01/07  mpd CWE139235/ Return METALIST, RELATIONSHIP_SET,
//                  CWE141623  DDL_LIST to Topaz.
//  2019/01/14  mpd CWE139235/ Accept EXECLREQ load request type.
//                  CWE141054
//  2019/01/16  mpd CWE139235/ Recompile for comtopaz changes.
//                  CWE142076
//  2019/01/18  tjs cwe142845  Implement 1008, 1009 changes.
//  2019/02/05  JHR CWE143153  Add "DDL only" to XFRRMETA parm list
//  2019/02/27  mpd CWE139235/ Handle FRPRGRES progress interval
//                  CWE144402  for extract or load.
//  2019/04/03  tjs cwe146334  add multiblock input to trace file
//
//  04/04/2019  JHR CWE146473  Add FRPROGRESSFILE XML ptr to comtopaz
//  06/05/2019  tjs cwe149121  Add return code for XFRTBMET()
//  06/17/2019  JHR CWE149503  This JIRA was opened thinking we had a
//                             problem with larger rquests.  We didn't,
//                             but while working on that I fixed where
//                             getting mb buffer.  We were getting too
//                             much.  You just need enough to hold what
//                             is in the length field.  Don't multiply
//                             by the number of blocks.
//                             Also found that when tracing the request
//                             the index field needs to be unsigned int.
//                             Offset needs to 8 characters on printline
//  06/12/2019  tjs cwe149470  Correct return code handling from XFRHCONN()
//  08/09/2019  JHR CWE140756/ Add JCLOUT support to execute extract and
//                  CWE149678  load request.
//  09/04/2019  mpd CWE117282/ Changes for MVS objects
//                  CWE152292
//  09/11/2019  JHR CWE117282/ Call xfrrlimp to import relationships
//                  CWE152660  and meta data
//  12/12/2019  tjs cwe155431  implement new api for RI for mult tables
//  01/08/2020  tjs cwe156376  add ddlflag stuff
//  02/05/2020  mpd CWE147671  CMSC mbr missing causes abend.
//  02/06/2020  jhr CWE156756  Change naming convention of trace dsn.
//  02/26/2020  tjs cwe158646  Make MVS dataset list easier to process
//                             for transaction 1009
//  02/27/2020  tjs cwe158645  add 1012, dsatt for dataset list
//  04/13/2020  YXT CWE153670/ Call XVJPRMLW to retrieve File-AID parm
//                  CWE160866  info and write it to trace file.
//  07/16/2020  tjs cwe165299  handle new prefix/suffix in init call
//  07/22/2020  NZP CWE164596  TERM request not honored.
//____________________________________________________________________
#ifndef  XFRRSRVR
#define  XFRRSRVR
#endif
#include <stddef.h>
#include <stdlib.h>                                          //20130403
#include <signal.h>
#include <setjmp.h>
#include <time.h>
#include <errno.h>
#include <leawi.h>       // for abend diagnosis
#include <ceeedcct.h>                              //D0017425
#include <dynam.h>
// Uncommenting the following will activate a number of "printf" statements to a
//   in debugging.
/*
#define Dbg_Mode
 */
//
#include "comcr94l.inc"
#include "comcr94s.inc"
#include "comcpyrt.inc"
#include "gbvisraf.inc"
#define MACRO
#include "fxxplist.inc"
#include "prmsdrcv.inc"
#include "prmsrvcs.inc"
#include "comdvs.inc"                                     //D0017439
#include "comsubvt.inc"
#include "comciovt.inc"
#include "comemc.inc"
#include "comioc.inc"

#include "comfavt.inc"                //cwe158645
#include "comreli.inc"                //cwe158645
#include "comdsatt.inc"               //cwe158645

#include "comgcb.inc"                                     //D0017439
#include "prmrdxgs.inc"                                   //D0017439
#include "prmrddrv.inc"                                   //D0017439
#include "xmrtdprv.inc"
#include "prmraf.inc"
#include "cwasmsrv.inc"
#include <ddinfo.h>                                          //20130327
#include "prmhrelu.inc"                                   //CWE101609
#include "os.inc"                                          //CWE103802
#include "xvjopunv.inc"                                    //CWE103802
#include "prmm2ds.inc"                                     //CWE138631

#include "prmgtmsg.inc"                                    //cwe138369
#include "prmcvmsg.inc"                                    //cwe138369
#include "prmfrt.inc"                                      //cwe138369

#include "comtopaz.inc"                                    //CWE137985
#include "prmtblst.inc"                                    //cwe142845
#include "prmtbmet.inc"                                    //cwe142845
#include "prmrlimp.inc"                                      //CWE152660
#include "prmlwprm.inc"                                      //CWE153670
#include "xvjprmm.inc"                                       //CWE153670
#include "xvjdb2m.inc"                                       //CWE153670
/*---------------------------------------*/
/*    #define error codes                */
/*---------------------------------------*/
#define    RDXE506     -2506                                 //cwe142845
#define    RDXEE201    -7201                                 //cwe138369
#define    RDXEE282    -7282                                 //cwe138369
#define    RDXEE408    -7408                                 //cwe107575
#define    RDXEE403    -7403                                 //cwe107575
#define    RDXEE401    -7401                                 //cwe107575
#define    RDXEE409    -7409                                 //cwe107575
#define    RDXEE410    -7410                                 //cwe107575
#define    RDXEE425    -7425
#define    RDXEE430    -7430              //UNKNOWN_REQ      //CWE101609
#define    RDXEE436    -7436                                 //CWE140500
#define    RDXE099     -2099                            //cwe158645

struct FXSERV_Parms
{
  struct prmsrvcs  *prmsrvcs;            // addr of prmsrvcs (in FXSERVER)
  int              *ecb_func_compl;      // addr of ECB for signalling I am comp
  int              *ecb_wake_up;         // addr of ECB to wake me up
  char             *xfr_flag;            // addr of FRFLAG (major signal flag)
#define FRABEND '\x01'
  char             *tpx_out_buf;         // addr of output buffer
  int              *tpx_bufsz;           // addr of buffer size (length of data
  int              *tpx_bufln;           // addr of buffer length (length of rec
  struct prmsdrcv  *prm_sdrcv;           // addr of parameters for send/receive
  int              *ecb_sdrcv;           // addr of ECB for send/receive
  char             *tpx_dsn_hlq;         // addr of DSN high level qualifier
  char             *tpx_in_buf;          // addr of input buffer
  struct xmlplist  *xmlplist;            // addr of parsed XML
};

struct Msg_Dtl
{
  char              rc[3];
  char              msgid[9];
  char              severity[2];
  char              msg_txt[81];
  char              msg_dtl[241];
};

struct multi_block_data                                  //CWE101609
{                                                        //CWE101609
  unsigned int      buff_size;                           //CWE101609
  unsigned int      used_size;                           //CWE101609
  char             *buffer;                              //CWE101609
};                                                       //CWE101609

// status of processing
char                proc_status;     // A: abend termination is being done
                                     // D: detail request being worked on
                                     // I: initialized,
                                     // S: relationship summary data being prepa
                                     // T: terminating,
                                     // X: exit (Abrupt Shutdown)
                                     // U: uninitialized,

struct comgcb      *comgcb;
_INT4               abend_tok;
static jmp_buf      jmp_ctl;

//
// internal functions
//

static void         Abnd_Exit (int);
static void         Get_Parms (struct FXSERV_Parms *, int, char **);

static void         Trace_Inp (struct FXSERV_Parms *, FILE *);       //cwe134588

static void         Cleanup (struct FXSERV_Parms *, struct PrmRAF *);

static void         Proc_Term (struct Gbl_Vis_Data
                               *gbl_vis_data,
                               char *xml_data,
                               struct Msg_Dtl *);

static short        Get_Multi_Block_Data (struct multi_block_data *,
                                          struct FXSERV_Parms *,
                                          short,
                                          struct PrmRAF *,
                                          void **,              //CWE101609
                                          FILE *);              //cwe134588

//static void       Initialize_Environ (struct comgcb **, struct PrmRAF *);   CW
static short        Initialize_Environ (struct comgcb **, struct PrmRAF *); //CW
static void         Abend_Reporter (_FEEDBACK *, _INT4 *, _INT4 *, _FEEDBACK *);
static void         Find_LM (char *, unsigned int);                       //D001
static short        Geterrmsg (struct PrmRAF *);

// build linked list of db2 tables or mvs layout/01 level names CWE152293/cwe142
//static int          bldcrtb (struct xmlplist *,           //CWE152293/cwe14284
static int          bldobjtab (struct xmlplist *,           //CWE152293
                             struct multi_block_data *mb_data, //cwe142845
                             struct prmtbmet *,                //cwe142845
                             char *);                       //CWE152293

// convert hex string to displayable characters            //cwe138369
static void         hex2chr (int   length,                 //cwe138369
                             char *data_in,                //cwe138369
                             char *data_back);             //cwe138369

// dump the execreq input data                               cwe137432
//static void         prreqinfo (struct xmlplist *xmlplist); //cwe137432
static void         prreqinfo (struct xmlplist *xmlplist,    //cwe137432
                               struct multi_block_data *mb_data); //cwe146334

// dump the ri_load input data
static void         prrildinfo (struct xmlplist *xmlplist); //cwe137432

//static void         dmptbcr (struct prmtbmet *prmtbmet);  //CWE152293/cwe14284
static void         dmpobjtbl (struct prmtbmet *prmtbmet);  //CWE152293
static void         dmptbmeta (struct prmtbmet *prmtbmet);    //cwe142845

static short        scanrels (struct Rel_Sel  *relhead,      //cwe155431
                              struct tab_list *tbptr);       //cwe155431

static void         addrele (struct Rel_Sel      *relhead,   //cwe155431
                             struct Rel_Lst_Ent  *relptr);   //cwe155431

static short        Convert_to_Hex (char *hex_out,           //cwe155431
                                    char *char_in,           //cwe155431
                                    short len);              //cwe155431

static void         dmprelhd (struct Rel_Sel *relhead);      //cwe155431
static void         dmphex (char *instr, int   len);         //cwe155431

//
// external functions
extern void         xfrRAF (struct PrmRAF *);
extern void         XFRXENCD (struct PrmRAF *);
extern short        XFRHCONN (struct comgcb *, char *);
extern short        XFRHRELU (struct prmhrelu *);
extern void         XFRRIDAT (struct PrmRAF *);                        //CWE1016

extern short        XFRPOPUL (struct comgcb   *,             //cwe138369
                              struct comtopaz *,             //cwe138369
                              struct PrmRAF   *);            //cwe138369

extern short        XFRALAT (struct comtopaz *);             //cwe138369
extern short        XFRRMETA(struct comgcb *, char *, char *,//CWE141623
                             ioBlock_t *,                    //CWE141623
                             char);                          //CWE143153

//extern short        XFRM2DS (struct prmm2ds *);              //cwe138631
extern void         xfrm2ds (struct prmm2ds *);              //cwe138631

//extern  void       XFRTBMET (struct prmtbmet *);           //cwe142845
extern  short       XFRTBMET (struct prmtbmet *);          //cwe149121

// debug file pointer and flag                    //cwe134588
FILE                *xfrtrc = NULL;               //cwe134588
short               diag_ind = 0;                 //cwe134588

// if the trace file format needs to change we can do that here
#define TRACEMLQ  "FARDX.TRACE"
// new one, shorter to allow for long prefix             cwe165299
//#define TRACEMLQ_V2  "TRACE"                           //cwe165299

void
main(int argc, char *argv[])
{
  short               req_code;
  int                 jmp_rc;
  struct prmsdrcv    *sd_rcv_prm;
  static struct FXSERV_Parms *fx_parms=NULL;
  static FILE        *trc_file=NULL;
  struct PrmRAF       prmraf;
  struct xmlplist    *xmlplist;                            //CWE101609
  struct prmhrelu     prmhrelu;                            //CWE101609
  struct Vis_RAF_Out  vis_raf_out;                          //D0017439
  struct Err_Dtl      err_dtl;                              //D0017439
  struct Gbl_Vis_Data gbl_vis_data;
  ioBlock_t          *xml_ctl;
  struct xvjopunv    *xvjopunv;                            //CWE103802
  struct def_tpdsa                                         //d0017216
  {                                                        //d0017216
    char              filler1[484];                        //d0017216
    char              tpfl1;                               //d0017216
    char              filler2[48];                         //d0017216
  }                  *tpdsa;                               //d0017216
  struct def_tpxib                                         //d0017216
  {                                                        //d0017216
    char              filler1[12];                         //d0017216
    struct def_tpdsa *tpdsa;                               //d0017216
    char              filler2[46];                         //d0017216
    char              tpxfl3;                              //d0017216
    char              filler3[417];                        //d0017216
  }                  *tpxib;                               //d0017216
  struct multi_block_data mb_data;                         //CWE101609
  int                 fx_buffer_len;
  void               *reg1;
  int                 skip_snd_rcv=0;
  int                 send_func=4;
  enum serviceCodes   op_post=POST_ECB;
  enum serviceCodes   op_wait_1=WAIT_ONE_ECB;
  short               rc;                                  //CWE101609
  short               grc = 0;
  char                xfr_flag;
  char                wto_msg[127];                        //D0017216-2
  char                xml_data[1024];

  char   term_resp_p1[] = "<FX><FAWB><FARDX><FRREQ>2</FRREQ>"; //E164596
  char   init_resp_p1[] = "<FX><FAWB><FARDX><FRREQ>1</FRREQ>";
  char   rc0[]          = "<RC>0</RC>";
  char   init_resp_p2[] = "</FARDX></FAWB></FX>";
  char   xml_setopt_acc[] = "<FX><FAWB><FARDX><FRREQ>10</FRREQ><RC>0</RC></FARDX
  char   xml_setopt_rej[] = "<FX><FAWB><FARDX><FRREQ>10</FRREQ><RC>16</RC>"
                            "<SRVMSG><MSGTEXT>REQUEST IS OUT OF ORDER</MSGTEXT><
                            "<SEVERITY>E</SEVERITY></SRVMSG></FARDX></FAWB></FX>
  // Following are state switches:
//char                loop_status;                            CWE147671
  char                loop_status = ' ';                    //CWE147671
#define CONT 'C'
#define TERM 'T'

  // make 'em shorts, works better for debugging             cwe134588
  short               resp_avail = 0;

  char                ssid[4];
  char               *orig_trans=0;                        //CWE101609
  int                 trans_len=1;                         //CWE101609

  short               ix;                                   //CWE103802
  short               mlib_alloc=1; // (value of 0 means DD found)  CWE103802
  short               japanese_support;                    //CWE103802
  char                alloc_txt[90];                        //CWE103802
  char                err_txt[80];                          //CWE103802
  char                wrk_str[80];                          //CWE103802

  short               trcdd = 0;                    //cwe134588

  struct comtopaz *comtopaz = NULL;                                 //cwe137985
  int             (*alat_FP) (struct comtopaz *) = NULL;     //cwe138369
  struct prmm2ds   prmm2ds;                                  //cwe138631
  //char             wkhlq [9];                                //cwe134588
  char             wkhlq [22];         //bigger for prefix    cwe165299
  struct presuf    *presuf = NULL;                          //cwe165299
  char             wksuf [22];                              //cwe165299
  char             wk_progress_char[9];                     //CWE144402
  char             wk_user[9];                               //CWE140500
  char            *wk_progress_ptr;                         //CWE144402
  long             wk_progress_long;                        //CWE144402
  short            wk_progress_digits;                      //CWE144402
  int              wk_code_page;                             //CWE140500
  char             wk_jcl [75];                              //cwe134588
  char             wk_jclx [146];                            //cwe134588
  int              jclsiz = 0;                               //cwe134588
  int              jclxsiz = 0;                              //cwe134588

  char             trcdsn [60];                              //cwe139432
  char             wrktime [7];                              //cwe139432
  char             wrkdate [7];                              //cwe139432
  struct  tm       *wktime;                                  //cwe139432
  time_t           wksecs;                                   //cwe139432
  char             wkuid [9];                                //cwe134588
  char             date_time[20];                            //cwe134588
  char             wkmsg1 [101]; // for xfrm2ds() msgs         cwe138631
  char             wkmsg2 [101]; // for xfrm2ds() msgs         cwe138631
  char             wk_extr_file_long[57];                   //CWE141623
  char             wk_extr_file[47];                        //CWE141623
  char             wk_extr_mbr[9];                          //CWE141623
  char             *lparen;                                 //CWE141623
  char             *rparen;                                 //CWE141623
  short            lparen_len;                              //CWE141623
  short            rparen_len;                              //CWE141623
  short            extr_len;                                //CWE141623
  ioBlock_t        *xfrrmeta_buf = NULL;                    //CWE141623
  char             db2_flag_1008_1009;                      //CWE152293

  struct prmtbmet  prmtbmet;                                //cwe142845
  struct prmrlimp  prmrlimp;                                 //CWE152660

  struct tab_list    *tbptr = NULL;           //cwe155431
  struct Rel_Sel     *relhead = NULL;         //cwe155431
  struct Rel_Lst_Ent *rel = NULL;             //cwe155431
  char               *mdmain = NULL;          //cwe155431
  char               *newmd = NULL;           //cwe155431
  int                 omdlen = 0;             //cwe155431
  int                 nmdlen = 0;             //cwe155431
  int                 hexlen = 0;             //cwe155431
  int                 len = 0;                //cwe155431

  short             (*facall_FP)();             //cwe158645
  short               facall_err = 0;           //cwe158645
  char                workstr [OBJ_PART1_LGTH]; //cwe158645
  char                errdsn  [OBJ_PART1_LGTH]; //cwe158645
  struct dsattlst    *currdslst = NULL;         //cwe158645
  struct dsattlst    *nextdslst = NULL;         //cwe158645
  struct dsattlst    *dslsthead = NULL;         //cwe158645
  struct tab_list    *currtb = NULL;            //cwe158645

  int               (*__asm_XVJPARM) () = NULL;              //CWE153670
  struct parmprm      parms;                                 //CWE153670
  struct xvjopdb2    *xvjopdb2;                              //CWE153670
  int               (*PRMLW_FP)      () = NULL;              //CWE153670
  int                 rc_prmlw, rc_xvjparm, i;               //CWE153670
  void               *parmout_pos;                           //CWE153670
  char                poutrec[80+1];                         //CWE153670
  struct PRMLWPRM     pw;                                    //CWE153670

  // Following is very helpful in debugging the abend handling code.
  // To use it, remove the comments, compile with OPTIONS=TEST, and then
  // at execution time the IBM debugger will automatically pop up (must
  // execute under TSO).
  //_VSTRING commands;
  //_FEEDBACK fc;

  //strcpy(commands.string, "");
  //commands.length = strlen(commands.string);
  //CEETEST(&commands, &fc);

  if (diag_ind)
  {
    fprintf (xfrtrc, "\nXFRRSRVR: entry point\n");               //cwe134588
    fflush (xfrtrc);                                             //cwe134588
  }

  memset(wto_msg, ' ', 126);                                              //D001
  proc_status = 'U';
  // D0017425 - removing this and replacing it with CEE mechanisms
  // D0017764 - removing the CEE handler and replacing it with the
  //   original C signal handling, but we are using the CEE reporting
  //   calls to get most of the information about the abend.  See Abnd_Exit.
  // Signal setting here. When abend happens, call Abnd_Exit function
  // to take C trace information, and mark abend flag, then post back
  // to FXSERVER. User abend 900 happens in FXSERVER. HCI global ESTAE
  // processes to take a dump and calls ABEND recovery routine in
  // FXSERVER. Then XFRRSRVR is called for Forcing TERM request.
  signal (SIGILL,  Abnd_Exit);
  signal (SIGSEGV, Abnd_Exit);
  signal (SIGABND, Abnd_Exit);
  signal (SIGABRT, Abnd_Exit);
  xmlplist = NULL;                                                        //CWE1
  memset(&mb_data, '\0', sizeof(struct multi_block_data));                //CWE1
  jmp_rc = setjmp(jmp_ctl);
  if (jmp_rc != 0)
  {
    proc_status = 'A';
    // If an abend happens before initialization has been done,
    // continue with initialization (and hope we don't abend in
    // initialization).
  }

  if (fx_parms == NULL)
  {
    memset(&gbl_vis_data, '\0', sizeof(struct Gbl_Vis_Data));
    memset(&vis_raf_out, '\0', sizeof(struct Vis_RAF_Out));                  //D
    memset(&prmraf, '\0', sizeof(struct PrmRAF));
    memset(&err_dtl, '\0', sizeof(struct Err_Dtl));                          //D
    prmraf.vis_raf_out = &vis_raf_out;                                       //D
    prmraf.err_dtl = &err_dtl;                                               //D
    prmraf.gbvisraf = &gbl_vis_data;
//  Initialize_Environ(&comgcb, &prmraf);                     CWE147671
    rc = Initialize_Environ(&comgcb, &prmraf);              //CWE147671

    if (rc)                                                 //CWE147671
    {                                                       //CWE147671
      //WTO message from initialization failure.              CWE147671
      memcpy(wto_msg, comgcb->comdvs->rdtch1, 126);         //CWE147671   //D001
      WTO(wto_msg);                                         //CWE147671   //D001
    }                                                       //CWE147671
    else                                                    //CWE147671
    {                                                       //CWE147671
      // allocate the fx parms struct, and initialize it from argv
      // using Get_Parms(); note that Get_Parms() expects there to
      // be exactly 10 arguments sent to this program. each of these
      // arguments is an address that then gets put in fx_parms
      fx_parms = (struct FXSERV_Parms *)malloc(sizeof(struct FXSERV_Parms));
      memset(fx_parms, '\0', sizeof(struct FXSERV_Parms));
      Get_Parms(fx_parms, argc, argv);

      sd_rcv_prm = fx_parms->prm_sdrcv;
      fx_buffer_len = *fx_parms->tpx_bufln;
      tpxib = (struct def_tpxib *)fx_parms->tpx_in_buf;                     //d0
      prmraf.cease_ind = &tpxib->tpxfl3;                                    //d0
      prmraf.cease_value = 0x01;                                            //d0
      tpdsa = tpxib->tpdsa;                                                 //d0
      prmraf.discon_value = 0x10;                                           //d0
      prmraf.discon_ind = &tpdsa->tpfl1;                                    //d0
    }                                                       //CWE147671
  }

  //CEE3SRP(&abend_tok, &fc);      // Set Return Point after ABEND         D0017
  if (proc_status == 'A')                                              //D001742
  {
    // If an abend is intercepted we will jump here where we set up    //D001742
    // a response for the WB.
    err_dtl.err_code = RDXEE408;                                       //CWE1075
    XFRXENCD(&prmraf);    // Encode the output into XML                  D001742
    resp_avail = 0;                                                    //CWE1016
    printf("\nReturn from encoding the Error");
    loop_status = TERM;                                                //CWE1016
    //  goto FORCE_EXIT;                                                   //CWE
  }                                                                    //D001742


  mlib_alloc = osddinfo("rdxmlib", NULL, NULL, NULL, NULL, NULL);//CWE103802
  if (mlib_alloc != 0)                                      //CWE103802
  {                                                                  //CWE103802
    xvjopunv = 0;                                                    //CWE103802
    if (comgcb)                                                      //CWE103802
      xvjopunv = comgcb->xvjopunv;                                   //CWE103802
    if (xvjopunv)                                                    //CWE103802
    {                                                                //CWE103802
      if (xvjopunv->DBCS_support == 'Y')                             //CWE103802
        japanese_support = 1;                                        //CWE103802
      memcpy(wrk_str, xvjopunv->smpe_msg_lib, 44);                   //CWE103802
      if (japanese_support)                                          //CWE103802
        memcpy(wrk_str, xvjopunv->smpe_jpn_msg_lib, 44);             //CWE103802
      for (ix=43; ix>0; ix--)                                        //CWE103802
      {                                                              //CWE103802
        if (wrk_str[ix] == ' ')                                      //CWE103802
          continue;                                                  //CWE103802
        break;                                                       //CWE103802
      }                                                              //CWE103802
      wrk_str[ix+1] = '\0';                                          //CWE103802
      memset (alloc_txt, 0, sizeof (alloc_txt));                     //CWE103802
      sprintf(alloc_txt, "ddn=rdxmlib,dsn=\'%s\',disp=shr", wrk_str);//CWE103802
      rc = osdynalloc(DYN_ALLOC, alloc_txt, err_txt);                //CWE103802
    }                                                                //CWE103802
                                                                     //CWE103802
    if (rc == 0)                                                     //CWE103802
      mlib_alloc = 0;                                                //CWE103802
    else                                                             //CWE103802
    {                                                                //CWE103802
      printf("\nError allocating RDXMLIB ");                         //CWE103802
    }                                                                //CWE103802
  }                                                                  //CWE103802


  // Upon entry to this program, the first request has already been made
  // available and is sitting in the buffer whose address has been passed
  // in to us.  Subsequent requests will come in after we write out our
  // responses in the main processing loop.

  // Main processing loop here
  if (diag_ind)
    fprintf (xfrtrc, "\nXFRRSRVR starting main processing loop.");     //cwe1345

  for (loop_status = CONT; loop_status == CONT;)
  {
    // Start of normal processing loop
    memset(sd_rcv_prm, '\0', sizeof(struct prmsdrcv));
    sd_rcv_prm->srxib = fx_parms->tpx_in_buf;
    sd_rcv_prm->srlast = 'N';
    sd_rcv_prm->srtrnslt = 'Y';

    resp_avail = 0;
    // CWE101609 - handle multi-block input here.  Note that being here
    //  multi-block input can come attached to ANY input transaction.
    //  If it is considered invalid, then each processing routine will
    //  have to decide if it is good, bad, or whatever.
                                                                     //CWE101609
    xmlplist = fx_parms->xmlplist;                                   //CWE101609
    if (xmlplist && xmlplist->mbnbyte > 0)                           //CWE101609
    {                                                                //CWE101609
      // must first save the existing transaction, because it will be  CWE101609
      //  wiped out by the receive that brings in the multi-block data.CWE101609
      if (orig_trans)                                                //CWE101609
      {                                                              //CWE101609
        free(orig_trans);                                            //CWE101609
        orig_trans = NULL;                                           //CWE101609
      }                                                              //CWE101609
      trans_len = fx_buffer_len;                                     //CWE101609
      orig_trans = malloc(trans_len);                                //CWE101609
      memcpy(orig_trans, xmlplist, trans_len);                       //CWE101609

      //rc = Get_Multi_Block_Data(&mb_data, fx_parms, diag_ind,        //CWE1016
      //     &prmraf, &reg1);                                          //CWE1016
      rc = Get_Multi_Block_Data (&mb_data, fx_parms, diag_ind,        //CWE10160
                                 &prmraf, &reg1, xfrtrc);             //cwe13458

      if (rc == 20 && diag_ind)                                      //CWE101609
        fprintf (xfrtrc, "\nCEASE or DISCONNECT detected in multiblock receive."
      if (rc == 20)                                                 //CWE101609
      {                                                             //CWE101609A
        loop_status = TERM;                                         //CWE101609A
        proc_status = 'X';                                          //CWE101609A
        resp_avail = 0;                                             //CWE101609A
        continue;                                                   //CWE101609A
        // This should have the same effect as goto Abrupt_Shutdown //CWE101609A
        //goto Abrupt_Shutdown;                                       //CWE10160
      }                                                             //CWE101609A
                                                                    //CWE101609
      if (rc)                                                       //CWE101609
      {                                                             //CWE101609
        prmraf.err_dtl->err_code = rc;                              //CWE101609
        XFRXENCD(&prmraf);                                          //CWE101609
        resp_avail = 1;                                             //CWE101609
        xml_ctl = prmraf.vis_raf_out->xml_ctl;                    //D0017439
        sd_rcv_prm->srdata = xml_ctl->ioBuffer;                   //D0017439
        sd_rcv_prm->srlen = xml_ctl->bufferSize - xml_ctl->bytesRemaining;//D001
        //loop_status = TERM;                             //CWE101609 CWE164596
        //proc_status = 'X';                              //CWE101609 CWE164596
        //continue;                                       //CWE101609 CWE164596
      }                                                             //CWE101609
    }                                                               //CWE101609

    if (diag_ind)
    {
      // add output file pointer
      //Trace_Inp(trc_file, fx_parms);
      Trace_Inp (fx_parms, xfrtrc);
    }

    req_code = fx_parms->xmlplist->u.fr.frreq;

    if (diag_ind)                                                     //cwe13458
    {
      time (&wksecs);                                            //cwe134588
      wktime = localtime (&wksecs);                              //cwe134588
      strftime (date_time, 20,"%Y/%m/%d %H:%M:%S", wktime);      //cwe134588
      fprintf (xfrtrc, "\n\n%s XFRRSRVR: req_code - %d",         //cwe134588
                 date_time, req_code);                           //cwe134588
    }

    // allocate the comtopaz here                             cwe165299
    if (comtopaz == NULL)
    {
      comtopaz = (struct comtopaz *) malloc (sizeof(struct comtopaz));  //cwe165
      if (comtopaz == NULL)                                   //cwe165299
      {                                                       //cwe165299
        // out of memory,                                     //cwe165299
        // TODO: set error flag, break out of loop            //cwe165299
      }                                                       //cwe165299
      memset (comtopaz, 0, sizeof (struct comtopaz));         //cwe165299

      // first things first                                     cwe165299
      memcpy (comtopaz->comtopaz_eyecatch, "COMTOPAZ", 8);    //cwe165299
      comtopaz->comgcb = comgcb;                              //cwe165299

      // get the prefix/suffix struct                         //cwe165299
      comtopaz->presuf = (struct presuf *) malloc (sizeof (struct presuf));  //c
      memset (comtopaz->presuf, 0, sizeof (struct presuf));   //cwe165299
    }

    switch (req_code)
    {
    case 1: // INIT request
      if (diag_ind && xfrtrc != NULL)
        fprintf (xfrtrc, "\nXFRRSRVR INIT request.");                  //cwe1345

      if (proc_status == 'U')
      {
        // version can be 1 or 2                                 cwe165299
        if (xmlplist->xmlvrsn == 1 ||                          //cwe165299
            xmlplist->xmlvrsn == 2)                            //cwe165299
        {
          memcpy (gbl_vis_data.user_id, xmlplist->u.fr.fruser, 8);
          gbl_vis_data.code_page = xmlplist->u.fr.frcp;
          gbl_vis_data.frtrace   = xmlplist->u.fr.frtrace;

          memset (wkhlq, 0, sizeof (wkhlq));                      //cwe134588
          // figure out what to use for prefix/suffix
          // use either hlq or userid, whichever was
          // sent by topaz user
          memcpy (wkhlq, xmlplist->u.fr.frdsnhlq,                 //cwe134588
                  sizeof (xmlplist->u.fr.frdsnhlq));              //cwe134588
          if (wkhlq[0] == ' ' ||                                  //cwe134588
              wkhlq[0] == 0)                                      //cwe134588
          {                                                       //cwe134588
            // no high level qualifier, use userid                //cwe134588
            memcpy (wkhlq, xmlplist->u.fr.fruser,                 //cwe134588
                    sizeof (xmlplist->u.fr.fruser));              //cwe134588
          }
          padnull (wkhlq, sizeof (wkhlq));                         //cwe165299

          presuf = comtopaz->presuf;
          if (xmlplist->xmlvrsn == 1)
          {
            // move either hlq or user to comtopaz presuf struct  cwe165299
            // with verion 1, ONLY HLQ will be used as prefix,    cwe165302
            // and no suffix will be used (init'd to null)        cwe165302
            memcpy (presuf->prefix, wkhlq, strlen (wkhlq));     //cwe165299
          }
          else if (xmlplist->xmlvrsn == 2)                      //cwe165299
          {
            // pull the prefix and suffix from the transaction    cwe165299
            //                                                    cwe165299
            // start with prefix, if we got one                   cwe165299
            if (xmlplist->u.fr.fr_prefix[0] != ' ' &&           //cwe165299
                xmlplist->u.fr.fr_prefix[0] != 0 )              //cwe165299
            {                                                   //cwe165299
              memset (wksuf, 0, sizeof (wksuf));                //cwe165299
              memcpy (wksuf,                                    //cwe165299
                      xmlplist->u.fr.fr_prefix,                 //cwe165299
                      sizeof (xmlplist->u.fr.fr_prefix));       //cwe165299
              padnull (wksuf, sizeof (wksuf));                  //cwe165299
              memcpy (presuf->prefix, wksuf, strlen (wksuf));   //cwe165299
            }
            else
            {
              // no prefix from topaz, so use hlq/uid           //cwe165299
              // (wkhlq has either hlq from init request,         cwe165302
              // or if no hlq was sent, it has uid; see above)    cwe165302
              memcpy (presuf->prefix, wkhlq, strlen(wkhlq));    //cwe165299
            }

            // get the suffix into comptopaz presuf             //cwe165299
            // ... if we got one from the user                  //cwe165299
            if (xmlplist->u.fr.fr_suffix[0] != ' ' &&           //cwe165299
                xmlplist->u.fr.fr_suffix[0] != 0 )              //cwe165299
            {
              memset (wksuf, 0, sizeof (wksuf));                //cwe165299
              memcpy (wksuf,                                    //cwe165299
                      xmlplist->u.fr.fr_suffix,                 //cwe165299
                      sizeof (xmlplist->u.fr.fr_suffix));       //cwe165299
              padnull (wksuf, 0, sizeof (wksuf));               //cwe165299
              memcpy (presuf->suffix, wksuf, strlen (wksuf));   //cwe165299
            }
          }   // end of version 1/2 condition

          // handle tracing                                              cwe1394
                                                                       //cwe1345
          // check for EXCLUSIVELY 'Y' (later, we might                //cwe1345
          // implement more flags, like E, extended, or                //cwe1345
          // D for SYSUDUMP, but for now, it's either Y                //cwe1345
          // or not Y)                                                 //cwe1345
          if (gbl_vis_data.frtrace == 'Y')                             //cwe1345
          {                                                            //cwe1345
            diag_ind = 1;                                              //cwe1345
                                                                       //cwe1345
            // use wkhlq to build dsn, then open the file              //cwe1345
            memset (trcdsn,  0, sizeof (trcdsn));                      //cwe1345
            memset (wrkdate, 0, sizeof (wrkdate));                     //cwe1345
            memset (wrktime, 0, sizeof (wrktime));                     //cwe1345
                                                                       //cwe1345
            // get time/date into strings we can use                   //cwe1345
            time (&wksecs);                                            //cwe1345
            wktime = localtime (&wksecs);                              //cwe1345
            strftime (wrkdate, sizeof (wrkdate), "%y%m%d", wktime);
            strftime (wrktime, sizeof (wrktime), "%H%M%S", wktime);

            // build trace dataset name
            sprintf (trcdsn, "'%s.%s.D%6.6s.T%6.6s'",
                     wkhlq, TRACEMLQ, wrkdate, wrktime);

            // name too long?                                        //cwe134588
            if (strlen (trcdsn) > 46)                                //cwe134588
            {                                                        //cwe134588
              trcdsn[45] = '\'';                                     //cwe134588
              trcdsn[46] = 0;                                        //cwe134588
            }                                                        //cwe134588
                                                                     //cwe134588
            xfrtrc = fopen (trcdsn, "w");                            //cwe134588
            if (xfrtrc == NULL)                                      //cwe134588
            {                                                        //cwe134588
              diag_ind = 0;  // stop trying to log                     cwe134588
              // baaaaaad
              printf ("\n%s: couldn't open '%s'\n", __FUNCTION__, trcdsn);
              printf ("            %s, Built: %s:%s\n", __DATE__, __TIME__);
            }
            else
            {
              // let the started task do debugging
              comtopaz->trace_file = (void *) xfrtrc;

              //CWE153670 Get File-AID parameters and put them in trace
              pw.prmlw_act     = PRMLW_GET;       //Set GET action
              pw.prmlw_poa@    = 0;  //Clear Parm Out Area address
              pw.prmlw_linecnt = 0;  //Clear parm line counter
              memcpy(pw.prmlw_taskpcd, "FR", 2);  //Set FR
              pw.prmlw_envno   = 0;  //Set env no 0
              // Get number of subsystems defined in XVJOPDB2
              loadm("XVJPARM", ((void(**)())&__asm_XVJPARM));
              if (__asm_XVJPARM)
              {
                memcpy(parms.prodid, "DB2", 3);
                parms.action = GETCCB;
                rc_xvjparm = (*__asm_XVJPARM) (&parms);
                if (!rc_xvjparm)
                {
                  xvjopdb2      = (struct xvjopdb2 *) parms.ccbaddr;
                  pw.prmlw_envno   = xvjopdb2->nbr_of_ssids;
                  parms.action = FREECCB;
                  rc_xvjparm = (*__asm_XVJPARM) (&parms);
                  xvjopdb2 = NULL;
                }
                unloadm((void(*)())&__asm_XVJPARM);
              }
              loadm("XVJPRMLW", ((void(**)())&PRMLW_FP));
              if (PRMLW_FP)
              {
                rc_prmlw = (*PRMLW_FP) (&pw);  //Call XVJPRMLW
                if (rc_prmlw < 8)
                {
                  //Write the paramters into trace file
                  memset(poutrec, 0x00, sizeof(poutrec));
                  parmout_pos = pw.prmlw_poa@;
                  for (i = 0; i < pw.prmlw_linecnt;  i++)
                  {
                    memcpy(poutrec, parmout_pos, 80);
                    fprintf(xfrtrc, "%s\n", poutrec);
                    parmout_pos += 80;
                  }
                  pw.prmlw_act = PRMLW_REL;  //Set REL action
                  rc_prmlw = (*PRMLW_FP) (&pw);  //Call XVJPRMLW
                }
                unloadm((void(*)())&PRMLW_FP);
              }
              //CWE153670 end
                                                                         //cwe13
              // print starting message                                  //cwe13
              time (&wksecs);                                            //cwe13
              wktime = localtime (&wksecs);                              //cwe13
              strftime (date_time, 20,"%Y/%m/%d %H:%M:%S", wktime);      //cwe13
              fprintf (xfrtrc, "\n%s XFRRSRVR: INIT request received\n", //cwe13
                       date_time);                                       //cwe13
              fprintf (xfrtrc, "                    %s, Built: %s:%s\n", //cwe13
                       __FILE__, __DATE__, __TIME__);                    //cwe13
              memset (wk_user, 0, sizeof (wk_user));        //CWE140500
              memcpy (wk_user, fx_parms->xmlplist->u.fr.fruser, 8); //CWE140500
              wk_code_page = fx_parms->xmlplist->u.fr.frcp; //CWE140500
              fprintf (xfrtrc, "\n%20.20sFRUSER   : %s", " ", wk_user);      //C

              //if (xmlplist->xmlvrsn == 1)                              //cwe16
              //  fprintf (xfrtrc, "\n%20.20sFRDSNHLQ : %s", " ", wkhlq);  //cwe
              //else if (xmlplist->xmlvrsn == 2)                          //cwe1
              // always pring hlq
              fprintf (xfrtrc, "\n%20.20sFRDSNHLQ : %s", " ", wkhlq);  //cwe1652

              // but only print prefix/suffix if we're in ver 2
              if (xmlplist->xmlvrsn == 2)                          //cwe165299
              {                                                         //cwe165
                // in version 2, we get prefix and suffix               //cwe165
                fprintf (xfrtrc, "\n%20.20sPREFIX : %20.20s",           //cwe165
                         " ", xmlplist->u.fr.fr_prefix);                //cwe165
                fprintf (xfrtrc, "\n%20.20sSUFFIX : %20.20s",           //cwe165
                         " ", xmlplist->u.fr.fr_suffix);                //cwe165
              }                                                         //cwe165
              fprintf (xfrtrc, "\n%20.20sFRCP     : %d", " ", wk_code_page); //C
            }                                                            //cwe13
          }   // end of "if (gbl_vis_data.frtrace == 'Y'  "              //cwe13

          // Now set up a response
          strcpy(xml_data, init_resp_p1);
          strcat(xml_data, rc0);
          strcat(xml_data, init_resp_p2);
          resp_avail = 1;
          proc_status = 'I';
          sd_rcv_prm->srdata = xml_data;
          sd_rcv_prm->srlen = strlen(xml_data);
        }
        else
        {
          // do not support less than V5
          // Set up a "not supported" response
          //err_dtl.err_code = -7403;  // Version incompatibility
          err_dtl.err_code = RDXEE403;                              //CWE107575
          resp_avail = 1;
          XFRXENCD(&prmraf);    // Encode the output into XML         D0016408
          xml_ctl = prmraf.vis_raf_out->xml_ctl;                    //D0017439
          sd_rcv_prm->srdata = xml_ctl->ioBuffer;                   //D0017439
          sd_rcv_prm->srlen = xml_ctl->bufferSize - xml_ctl->bytesRemaining;//D0
          //proc_status = 'T';                             //D0017439 CWE164596
          //loop_status = TERM;                                       CWE164596
          // 10/07/2014 - in testing this caused an "endless" wait, until I
          //  find a better way, I am going to "goto" FORCE_EXIT.
          //continue;                                    //CWE101609A CWE164596
          //goto FORCE_EXIT;                                           CWE101609
        }
      }
      else
      {
        // Got an INIT request out of order
        //err_dtl.err_code = -7401;  // msg sequence error           D0016408
        err_dtl.err_code = RDXEE401;                               //CWE107575
        XFRXENCD (&prmraf);    // Encode the output into XML           D0016408
        resp_avail = 1;
        xml_ctl = prmraf.vis_raf_out->xml_ctl;                    //D0017439
        sd_rcv_prm->srdata = xml_ctl->ioBuffer;                   //D0017439
        sd_rcv_prm->srlen = xml_ctl->bufferSize - xml_ctl->bytesRemaining;//D001
        //proc_status = 'T';                              //D0017439 CWE164596
        //loop_status = TERM;                                        CWE164596
        //continue; // This will take us out of main loop and get us   CWE101609
                  // to FORCE_EXIT.                                  CWE101609A
//      goto FORCE_EXIT;                                           //CWE101609A
      } // Got an INIT request out of order
      break;

    case 2: // TERM request
      if (diag_ind)
      {
        // get time/date into strings we can use                   //cwe134588
        time (&wksecs);                                            //cwe134588
        wktime = localtime (&wksecs);                              //cwe134588
        strftime (date_time, 20,"%Y/%m/%d %H:%M:%S", wktime);      //cwe134588
        fprintf (xfrtrc, "\n%s XFRRSRVR: TERM request received\n", //cwe134588
                 date_time);                                       //cwe134588

        // we close the trace file later, since we still have
        // stuff to write
      }

      proc_status = 'T';

      strcpy(xml_data, term_resp_p1);                               //cwe164596
      strcat(xml_data, rc0);                                        //cwe164596
      strcat(xml_data, init_resp_p2);                               //cwe164596
      sd_rcv_prm->srdata = xml_data;
      sd_rcv_prm->srlen = strlen(xml_data);
      resp_avail = 1;
      break;

    case 1000: // IMPORT request
      if (diag_ind)
        fprintf (xfrtrc, "\nXFRRSRVR IMPORT request.");           //cwe134588

      prmraf.req = fx_parms->xmlplist;
      xfrRAF(&prmraf);      // Build/arrange the data
      if (prmraf.rc == 20 && diag_ind)
        fprintf (xfrtrc, "\nCEASE or DISCONNECT detected by XFRRAF");   //cwe134
      if (prmraf.rc == 20)                               //d0017216
      {                                                             //CWE101609A
        loop_status = TERM;                                         //CWE101609A
        proc_status = 'X';                                          //CWE101609A
        resp_avail = 0;                                             //CWE101609A
        continue;                                                   //CWE101609A
        // This should have the same effect as goto Abrupt_Shutdown //CWE101609A
        //goto Abrupt_Shutdown;                            //d0017216 //CWE10160
      }                                                             //CWE101609A

      XFRXENCD(&prmraf);    // Encode the output into XML

      if (prmraf.rc == 20 && diag_ind)
        fprintf (xfrtrc, "\nCEASE or DISCONNECT detected by XFRXENCD");   //cwe1

      if (prmraf.rc == 20)                               //d0017216
      {                                                             //CWE101609A
        loop_status = TERM;                                         //CWE101609A
        proc_status = 'X';                                          //CWE101609A
        resp_avail = 0;                                             //CWE101609A
        continue;                                                   //CWE101609A
        // This should have the same effect as goto Abrupt_Shutdown //CWE101609A
//      goto Abrupt_Shutdown;                            //d0017216   CWE101609A
      }                                                             //CWE101609A
      if (prmraf.rc == 0)
        proc_status = 'S';
      // Send results to WB
      xml_ctl = prmraf.vis_raf_out->xml_ctl;
      sd_rcv_prm->srdata = xml_ctl->ioBuffer;
      sd_rcv_prm->srlen = xml_ctl->bufferSize - xml_ctl->bytesRemaining;
      resp_avail = 1;
      break;

    case 1001: // FILTER/DETAIL request
      if (diag_ind)
        fprintf (xfrtrc, "\nXFRRSRVR FILTER/DETAIL request.");      //cwe134588

      prmraf.req = fx_parms->xmlplist;
      xfrRAF(&prmraf);      // build/arrange the data
      if (prmraf.rc == 20 && diag_ind)
        fprintf (xfrtrc, "\nCEASE or DISCONNECT detected by XFRRAF");   //cwe134
      if (prmraf.rc == 20)                               //d0017216
      {                                                             //CWE101609A
        loop_status = TERM;                                         //CWE101609A
        proc_status = 'X';                                          //CWE101609A
        resp_avail = 0;                                             //CWE101609A
        continue;                                                   //CWE101609A
        // This should have the same effect as goto Abrupt_Shutdown //CWE101609A
//      goto Abrupt_Shutdown;                            //d0017216   CWE101609A
      }                                                             //CWE101609A
      XFRXENCD(&prmraf);    // Encode the output into XML
      if (prmraf.rc == 20 && diag_ind)
        fprintf (xfrtrc, "\nCEASE or DISCONNECT detected by XFRXENCD");   //cwe1
      if (prmraf.rc == 20)                               //d0017216
      {                                                             //CWE101609A
        loop_status = TERM;                                         //CWE101609A
        proc_status = 'X';                                          //CWE101609A
        resp_avail = 0;                                             //CWE101609A
        continue;                                                   //CWE101609A
        // This should have the same effect as goto Abrupt_Shutdown //CWE101609A
        //  goto Abrupt_Shutdown;                        //d0017216   CWE101609A
      }                                                             //CWE101609A
      if (prmraf.rc == 0)
        proc_status = 'D';
      // Send results to WB
      xml_ctl = prmraf.vis_raf_out->xml_ctl;
      sd_rcv_prm->srdata = xml_ctl->ioBuffer;
      sd_rcv_prm->srlen = xml_ctl->bufferSize - xml_ctl->bytesRemaining;
      resp_avail = 1;
      if (diag_ind)
        fprintf (xfrtrc, "\nXFRRSRVR send detail data response.");      //cwe134
      break;

    case 1002: // GETRIREL      request                                 //CWE101
      if (diag_ind)                                                     //CWE101
      {
        fprintf (xfrtrc, "\n%s GETRIREL\n", __FILE__);                //cwe13458
        // dump the ri_load data
        // need to test
        //prrildinfo (prmraf.req);
      }

      prmraf.req = fx_parms->xmlplist;                                  //CWE101
      memcpy (ssid, prmraf.req->u.fr.fr_ssid, 4);                //CWE101556

      err_dtl.err_code = XFRHCONN (comgcb, ssid);                   //CWE101556
      rc = err_dtl.err_code;
      if (diag_ind)
      {
        time (&wksecs);
        wktime = localtime (&wksecs);
        strftime (date_time, 20,"%Y/%m/%d %H:%M:%S", wktime);
        fprintf (xfrtrc, "\n%s XFRHCONN rc: %d, ssid: '%4.4s'",
                          date_time, rc, ssid);
      }

      //if (rc == 0)                        cwe149470
      // rc of 4 is ok                      cwe149470
      if (rc == 0 || rc == 4)             //cwe149470
      {
        XFRRIDAT (&prmraf);      // build/arrange the data                 //CWE

        if (diag_ind)                                                     //cwe1
          fprintf (xfrtrc,"\nXFRRIDAT rc: %d\n", prmraf.rc);                //cw

        if (prmraf.rc == 20 && diag_ind)                                    //CW
          fprintf (xfrtrc,"\nCEASE or DISCONNECT detected by XFRRIDAT");   //cwe

        if (diag_ind)                                  //cwe134588
          fflush (xfrtrc);                             //cwe134588

        if (rc == 20)                                                  //CWE1015
        {                                                             //CWE10160
          loop_status = TERM;                                         //CWE10160
          proc_status = 'X';                                          //CWE10160
          resp_avail = 0;                                             //CWE10160
          continue;                                                   //CWE10160
          // This should have the same effect as goto Abrupt_Shutdown //CWE10160
          // goto Abrupt_Shutdown;                       //d0017216   //CWE10160
        }                                                             //CWE10160
      }

      XFRXENCD (&prmraf);    // Encode the output into XML               //CWE10

      // did that work?
      if (prmraf.rc && diag_ind)                                   //cwe134588
      {
        fprintf (xfrtrc,"\nXFRXENCD rc: %d", prmraf.rc);                   //cwe
        fflush (xfrtrc);
      }

      if (prmraf.rc == 20 && diag_ind)                                  //CWE101
        fprintf (xfrtrc,"\nCEASE or DISCONNECT detected by XFRXENCD");  //cwe134

      if (prmraf.rc == 20)                                              //CWE101
      {                                                             //CWE101609A
        loop_status = TERM;                                         //CWE101609A
        proc_status = 'X';                                          //CWE101609A
        resp_avail = 0;                                             //CWE101609A
        continue;                                                   //CWE101609A
        // This should have the same effect as goto Abrupt_Shutdown //CWE101609A
        // goto Abrupt_Shutdown;                                    //CWE101609A
      }                                                             //CWE101609A

      if (prmraf.rc == 0)                                               //CWE101
        proc_status = 'D';                                              //CWE101

      // Send results to WB                                             //CWE101
      xml_ctl = prmraf.vis_raf_out->xml_ctl;                            //CWE101
      sd_rcv_prm->srdata = xml_ctl->ioBuffer;                           //CWE101
      sd_rcv_prm->srlen = xml_ctl->bufferSize - xml_ctl->bytesRemaining;//CWE101
      resp_avail = 1;                                                   //CWE101

      if (diag_ind)                                                     //CWE101
      {
        fprintf (xfrtrc, "\nXFRRSRVR send GETRIREL data response.");     //cwe13

        fprintf (xfrtrc, "\n      struct prmsdrcv contents:");
        fprintf (xfrtrc, "\n              char *srdata   %p", sd_rcv_prm->srdata
        fprintf (xfrtrc, "\n              char *srxib    %p", sd_rcv_prm->srxib
        fprintf (xfrtrc, "\n               int  srlen    %d", sd_rcv_prm->srlen
        fprintf (xfrtrc, "\n               int  srtrnsmt %d", sd_rcv_prm->srtrns
        fprintf (xfrtrc, "\n              char  srtrnslt %c", sd_rcv_prm->srtrns
        fprintf (xfrtrc, "\n              char  srlast   %c", sd_rcv_prm->srlast
        fprintf (xfrtrc, "\n              char  sr64bit  %c", sd_rcv_prm->sr64bi
      }

      break;                                                            //CWE101

    case 1003: // PROCRELS      request                                 //CWE101
      if (diag_ind)                                                     //CWE101
        fprintf (xfrtrc, "\nXFRRSRVR PROCRELS  request.");           //cwe134588

      prmraf.req = (struct xmlplist *)orig_trans;                       //CWE101
      memcpy(ssid, prmraf.req->u.fr.fr_ssid, 4);                //CWE101556
      rc = err_dtl.err_code = XFRHCONN(comgcb, ssid);                   //CWE101
      if (diag_ind)
      {
        time (&wksecs);
        wktime = localtime (&wksecs);
        strftime (date_time, 20,"%Y/%m/%d %H:%M:%S", wktime);
        fprintf (xfrtrc, "\n%s XFRHCONN rc: %d, ssid: '%4.4s'",
                          date_time, rc, ssid);
      }

      //if (rc == 0)                        cwe149470
      // rc of 4 is all right               cwe149470
      if (rc == 0 || rc == 4)             //cwe149470
      {
        // Must fill in prmhrelu instead of prmraf.
        //  Input will mostly be a buffer filled with multi-block data.
        memset(&prmhrelu, '\0', sizeof(struct prmhrelu));               //CWE101
        prmhrelu.func = ' ';                                            //CWE101
        prmhrelu.comgcb = comgcb;                                       //CWE101
        prmhrelu.req = (struct xmlplist *)orig_trans;                   //CWE101
        prmhrelu.buff_len = mb_data.buff_size;                          //CWE101
        prmhrelu.used_len = mb_data.used_size;                          //CWE101
        prmhrelu.buff = mb_data.buffer;                                 //CWE101
        prmhrelu.cease_ind = prmraf.cease_ind;                          //CWE101
        prmhrelu.cease_value = prmraf.cease_value;                      //CWE101
        prmhrelu.discon_value = prmraf.discon_value;                    //CWE101
        prmhrelu.discon_ind = prmraf.discon_ind;                        //CWE101
        rc = XFRHRELU(&prmhrelu);      // build/arrange the data        //CWE101
      }

      if (orig_trans)                                                   //CWE101
      {                                                                 //CWE101
        free(orig_trans);                                               //CWE101
        orig_trans = NULL;                                              //CWE101
      }                                                                 //CWE101

      // Output from XFRHRELU will only be a message indicating completion.   //
      if (rc == 20 && diag_ind)                                         //CWE101
        fprintf (xfrtrc, "\nCEASE or DISCONNECT detected by XFRHRELU");    //cwe

      if (rc == 20)                                                     //CWE101
      {                                                             //CWE101609A
        loop_status = TERM;                                         //CWE101609A
        proc_status = 'X';                                          //CWE101609A
        resp_avail = 0;                                             //CWE101609A
        continue;                                                   //CWE101609A
        // This should have the same effect as goto Abrupt_Shutdown //CWE101609A
        // goto Abrupt_Shutdown;                                    //CWE101609A
      }                                                             //CWE101609A

      if (rc != 0)                                                  //CWE101609
      {                                                             //CWE101609
        err_dtl.err_code = rc;                                      //CWE101609
        XFRXENCD(&prmraf);    // Encode the output into XML         //CWE101609
        xml_ctl = prmraf.vis_raf_out->xml_ctl;                    //D0017439
        sd_rcv_prm->srdata = xml_ctl->ioBuffer;                   //D0017439
        sd_rcv_prm->srlen = xml_ctl->bufferSize - xml_ctl->bytesRemaining;//D001
        resp_avail = 1;                                             //CWE101609
      }                                                             //CWE101609

      if (prmraf.rc == 20 && diag_ind)                              //CWE101609
        fprintf (xfrtrc, "\nCEASE or DISCONNECT detected by XFRXENCD");   //cwe1

      if (rc == 20)                                                 //CWE101609
      {                                                             //CWE101609A
        loop_status = TERM;                                         //CWE101609A
        proc_status = 'X';                                          //CWE101609A
        resp_avail = 0;                                             //CWE101609A
        continue;                                                   //CWE101609A
        // This should have the same effect as goto Abrupt_Shutdown //CWE101609A
        // goto Abrupt_Shutdown;                                    //CWE101609A
      }                                                             //CWE101609A

      if (rc == 0)                                                      //CWE101
        proc_status = 'D';                                              //CWE101

      // Send results to WB                                             //CWE101
      xml_ctl = prmraf.vis_raf_out->xml_ctl;                            //CWE101
      sd_rcv_prm->srdata = xml_ctl->ioBuffer;                           //CWE101
      sd_rcv_prm->srlen = xml_ctl->bufferSize - xml_ctl->bytesRemaining;//CWE101
      if (diag_ind)                                                     //CWE101
      {
        fprintf (xfrtrc, "\nXFRRSRVR send PROCREL response.");        //cwe13458
        fflush (xfrtrc);
      }

      break;                                                            //CWE101

    case 1004: // LOADRIREL     request                                 //CWE103
      if (diag_ind)                                                     //CWE103
        fprintf (xfrtrc, "\nXFRRSRVR LOADRIREL request.");           //cwe134588
      prmraf.req = (struct xmlplist *)orig_trans;                       //CWE103
      memcpy(ssid, prmraf.req->u.fr.fr_ssid, 4);                //CWE103449
      rc = err_dtl.err_code = XFRHCONN(comgcb, ssid);                   //CWE103
      if (diag_ind)
      {
        time (&wksecs);
        wktime = localtime (&wksecs);
        strftime (date_time, 20,"%Y/%m/%d %H:%M:%S", wktime);
        fprintf (xfrtrc, "\n%s XFRHCONN rc: %d, ssid: '%4.4s'",
                          date_time, rc, ssid);
      }

      //if (rc == 0)                        cwe149470
      // rc of 4 is all right               cwe149470
      if (rc == 0 || rc == 4)             //cwe149470
      {                                                                 //CWE103
        // Must fill in prmhrelu instead of prmraf.                     //CWE103
        //  Input will mostly be a buffer filled with multi-block data. //CWE103
        memset(&prmhrelu, '\0', sizeof(struct prmhrelu));               //CWE103
        prmhrelu.func = ' ';                                            //CWE103
        prmhrelu.comgcb = comgcb;                                       //CWE103
        prmhrelu.req = (struct xmlplist *)orig_trans;                   //CWE103
        prmhrelu.buff_len = mb_data.buff_size;                          //CWE103
        prmhrelu.used_len = mb_data.used_size;                          //CWE103
        prmhrelu.buff = mb_data.buffer;                                 //CWE103
        prmhrelu.cease_ind = prmraf.cease_ind;                          //CWE103
        prmhrelu.cease_value = prmraf.cease_value;                      //CWE103
        prmhrelu.discon_value = prmraf.discon_value;                    //CWE103
        prmhrelu.discon_ind = prmraf.discon_ind;                        //CWE103
        rc = XFRHRELU(&prmhrelu);      // build/arrange the data        //CWE103
        err_dtl.err_code = rc;
      }                                                                 //CWE103

      if (orig_trans)                                                   //CWE101
      {                                                                 //CWE101
        free(orig_trans);                                               //CWE101
        orig_trans = NULL;                                              //CWE101
      }                                                                 //CWE101

      if (rc == 20 && diag_ind)                                         //CWE103
        fprintf (xfrtrc, "\nCEASE or DISCONNECT detected by XFRRILOD");    //cwe

      if (rc == 20)                                                     //CWE103
      {                                                                 //CWE103
        loop_status = TERM;                                             //CWE103
        proc_status = 'X';                                              //CWE103
        resp_avail = 0;                                                 //CWE103
        continue;                                                       //CWE103
        // This should have the same effect as goto Abrupt_Shutdown     //CWE103
        // goto Abrupt_Shutdown;                                        //CWE103
      }                                                                 //CWE103
      if (rc != 0)                                                      //CWE103
      {                                                                 //CWE103
        err_dtl.err_code = rc;                                          //CWE103
        XFRXENCD(&prmraf);    // Encode the output into XML             //CWE103
        resp_avail = 1;                                                 //CWE103
        xml_ctl = prmraf.vis_raf_out->xml_ctl;                    //D0017439
        sd_rcv_prm->srdata = xml_ctl->ioBuffer;                   //D0017439
        sd_rcv_prm->srlen = xml_ctl->bufferSize - xml_ctl->bytesRemaining;//D001
      }                                                                 //CWE103
      // Send results to WB                                             //CWE103
      // Output from XFRHRELU is already encoded.                       //CWE104
      xml_ctl = prmhrelu.xml_ctl;                                       //CWE104
      if (rc == 0 && xml_ctl && xml_ctl->ioBuffer)                      //CWE104
      {                                                                 //CWE103
        resp_avail = 1;       // The output should be in the XML buffer //CWE103
        sd_rcv_prm->srdata = xml_ctl->ioBuffer;                         //CWE104
        sd_rcv_prm->srlen = xml_ctl->bufferSize - xml_ctl->bytesRemaining;//CWE1
        if (diag_ind)                                                   //CWE103
          fprintf (xfrtrc, "\nXFRRSRVR send LOADRIREL data response.");    //cwe
      }                                                                 //CWE103
      break;                                                            //CWE103

    //E137442 START
    case 1005: // EXECEREQ
    case 1006: // EXECLREQ                                 //CWE141054
      // get input request                                   cwe137985
      prmraf.req = fx_parms->xmlplist;                     //cwe137985

      // temporary code to check input XML
      if (diag_ind)
      {
        // dump the input received
        //prreqinfo (fx_parms->xmlplist);
        // possibly temporarily, dump the multiblock   cwe146334
        // data to help debug issues                   cwe146334
        prreqinfo (fx_parms->xmlplist, &mb_data);    //cwe146334
      }

      // put stuff from xvjopunv into comtopaz
      xvjopunv = comgcb->xvjopunv;
      memcpy (comtopaz->unit,
              xvjopunv->perm_unit,
              sizeof (xvjopunv->perm_unit));
      memcpy (comtopaz->mgmtclas,
              xvjopunv->temp_sms_mgmt_class,
              sizeof (xvjopunv->temp_sms_mgmt_class));
      memcpy (comtopaz->storclas,
              xvjopunv->temp_sms_strg_class,
              sizeof (xvjopunv->temp_sms_strg_class));
      comtopaz->use_dbcs = xvjopunv->DBCS_support;

      // move jobcards
      jclsiz = sizeof (comtopaz->JCL1);
      jclxsiz = sizeof (xmlplist->u.fr.fr_jclln1);

      memset (wk_jcl,  0, jclsiz);
      memset (wk_jclx, 0, jclxsiz);
      memcpy (wk_jclx, xmlplist->u.fr.fr_jclln1, jclxsiz);

      if (diag_ind)
        fprintf (xfrtrc, "\nJCL Line 1 in Hex : '%144.144s'\n", wk_jclx); //CWE1

      hex2chr (jclsiz, wk_jclx, wk_jcl);

      if (diag_ind)
        fprintf (xfrtrc, "JCL Line 1 in Char: '%72.72s'\n", wk_jcl); //CWE140500

      memcpy (comtopaz->JCL1, wk_jcl, jclsiz);

      memset (wk_jcl,  0, jclsiz);
      memset (wk_jclx, 0, jclxsiz);
      memcpy (wk_jclx, xmlplist->u.fr.fr_jclln2, jclxsiz);

      if (diag_ind)                                         //CWE140500
        fprintf (xfrtrc, "\nJCL Line 2 in Hex : '%144.144s'\n", wk_jclx); //CWE1

      hex2chr (jclsiz, wk_jclx, wk_jcl);

      if (diag_ind)                                         //CWE140500
        fprintf (xfrtrc, "JCL Line 2 in Char: '%72.72s'\n", wk_jcl);  //CWE14050

      memcpy (comtopaz->JCL2, wk_jcl, jclsiz);

      memset (wk_jcl,  0, jclsiz);
      memset (wk_jclx, 0, jclxsiz);
      memcpy (wk_jclx, xmlplist->u.fr.fr_jclln3, jclxsiz);

      if (diag_ind)                                         //CWE140500
        fprintf (xfrtrc, "\nJCL Line 3 in Hex : '%144.144s'\n", wk_jclx);  //CWE

      hex2chr (jclsiz, wk_jclx, wk_jcl);

      if (diag_ind)                                         //CWE140500
        fprintf (xfrtrc, "JCL Line 3 in Char: '%72.72s'\n", wk_jcl);  //CWE14050

      memcpy (comtopaz->JCL3, wk_jcl, jclsiz);

      memset (wk_jcl,  0, jclsiz);
      memset (wk_jclx, 0, jclxsiz);
      memcpy (wk_jclx, xmlplist->u.fr.fr_jclln4, jclxsiz);

      if (diag_ind)                                         //CWE140500
        fprintf (xfrtrc, "\nJCL Line 4 in Hex : '%144.144s'\n", wk_jclx);  //CWE

      hex2chr (jclsiz, wk_jclx, wk_jcl);

      if (diag_ind)                                         //CWE140500
        fprintf (xfrtrc, "JCL Line 4 in Char: '%72.72s'\n", wk_jcl);  //CWE14050

      memcpy (comtopaz->JCL4, wk_jcl, jclsiz);

      memset (wk_jcl,  0, jclsiz);
      memset (wk_jclx, 0, jclxsiz);
      memcpy (wk_jclx, xmlplist->u.fr.fr_jclln5, jclxsiz);

      if (diag_ind)                                         //CWE140500
        fprintf (xfrtrc, "\nJCL Line 5 in Hex : '%144.144s'\n", wk_jclx);  //CWE

      hex2chr (jclsiz, wk_jclx, wk_jcl);

      if (diag_ind)                                         //CWE140500
        fprintf (xfrtrc, "JCL Line 5 in Char: '%72.72s'\n", wk_jcl);  //CWE14050

      memcpy (comtopaz->JCL5, wk_jcl, jclsiz);

      // move javainfo overrides
      memset (comtopaz->fadebug_dsn,  ' ', sizeof (comtopaz->fadebug_dsn));    /
      memset (comtopaz->fajpath_dsn,  ' ', sizeof (comtopaz->fajpath_dsn));    /
      memset (comtopaz->fajopts_dsn,  ' ', sizeof (comtopaz->fajopts_dsn));    /
      memset (comtopaz->faipaddr_dsn, ' ', sizeof (comtopaz->faipaddr_dsn));   /
      memset (comtopaz->faexpath_dsn, ' ', sizeof (comtopaz->faexpath_dsn));   /
      memcpy (comtopaz->fadebug_dsn,  xmlplist->u.fr.fadebug,          //cwe1396
              sizeof (comtopaz->fadebug_dsn));                                 /
      PADSPACE (comtopaz->fadebug_dsn, sizeof (comtopaz->fadebug_dsn));        /
      memcpy (comtopaz->fajpath_dsn,  xmlplist->u.fr.fajpath,          //cwe1396
              sizeof (comtopaz->fajpath_dsn));                                 /
      PADSPACE (comtopaz->fajpath_dsn, sizeof (comtopaz->fajpath_dsn));        /
      memcpy (comtopaz->fajopts_dsn,  xmlplist->u.fr.fajopts,          //cwe1396
              sizeof (comtopaz->fajopts_dsn));                                 /
      PADSPACE (comtopaz->fajopts_dsn, sizeof (comtopaz->fajopts_dsn));        /
      memcpy (comtopaz->faipaddr_dsn, xmlplist->u.fr.faipaddr,         //cwe1396
              sizeof (comtopaz->faipaddr_dsn));                                /
      PADSPACE (comtopaz->faipaddr_dsn, sizeof (comtopaz->faipaddr_dsn));      /
      memcpy (comtopaz->faexpath_dsn, xmlplist->u.fr.faexpath,         //cwe1396
              sizeof (comtopaz->faexpath_dsn));                                /
      PADSPACE (comtopaz->faexpath_dsn, sizeof (comtopaz->faexpath_dsn));      /

      // move in JCLOUT dsn, if present; else set to NOT.USED              CWE14
      memset (comtopaz->jclout_dsn, ' ', sizeof (comtopaz->jclout_dsn)); //CWE14
      if (xmlplist->u.fr.frjclout[0] != ' ' &&                           //CWE14
          xmlplist->u.fr.frjclout[0] != NULL)                            //CWE14
      {                                                                  //CWE14
        memcpy (comtopaz->jclout_dsn, xmlplist->u.fr.frjclout,           //CWE14
                sizeof (comtopaz->jclout_dsn));                          //CWE14
      }                                                                  //CWE14
      else                                                               //CWE14
      {                                                                  //CWE14
        memcpy (comtopaz->jclout_dsn, "NOT.USED", 8);                    //CWE14
      }                                                                  //CWE14
      PADSPACE (comtopaz->jclout_dsn, sizeof (comtopaz->jclout_dsn));    //CWE14

//The progress interval can have these values:                CWE144402
// * = print the totals at Object end.                        CWE144402
// 0 = no progress interval printed.                          CWE144402
// Otherwise must be numeric.  The value will be multiplied   CWE144402
// by 1000 and saved.                                         CWE144402
      memset(wk_progress_char,0,sizeof(wk_progress_char));  //CWE144402
      memcpy(wk_progress_char, xmlplist->u.fr.frprogress,   //CWE144402
                sizeof(xmlplist->u.fr.frprogress));         //CWE144402
      if (diag_ind)                                         //CWE144402
        fprintf(xfrtrc,                                     //CWE144402
          "\nFRPRGRES Progress interval received=%s\n",     //CWE144402
          wk_progress_char);                                //CWE144402
      if (wk_progress_char[0] == ' ' ||                     //CWE144402
          wk_progress_char[0] == 0)                         //CWE144402
      {                                                     //CWE144402
        memcpy(comtopaz->frprogress, "NONE    ", 8);        //CWE144402
      }                                                     //CWE144402
      else                                                  //CWE144402
      {                                                     //CWE144402
        if (wk_progress_char[0] == '*')                     //CWE144402
        {                                                   //CWE144402
          memcpy(comtopaz->frprogress, "*       ", 8);      //CWE144402
        }                                                   //CWE144402
        else                                                //CWE144402
        {                                                   //CWE144402
          wk_progress_digits = 0;                           //CWE144402
          PADNULL(wk_progress_char,                         //CWE144402
                  sizeof(wk_progress_char));                //CWE144402
          wk_progress_ptr = &wk_progress_char[0];           //CWE144402
          for (ix=0; ix < sizeof(wk_progress_char);         //CWE144402
               ix++, wk_progress_ptr++)                     //CWE144402
          {                                                 //CWE144402
            if (*wk_progress_ptr == NULL)                   //CWE144402
              continue;                                     //CWE144402
            if (isdigit(*wk_progress_ptr))                  //CWE144402
            {                                               //CWE144402
              wk_progress_digits++;                         //CWE144402
              continue;                                     //CWE144402
            }                                               //CWE144402
          }                                                 //CWE144402
          if (wk_progress_digits !=                         //CWE144402
              strlen(wk_progress_char))                     //CWE144402
            memcpy(comtopaz->frprogress, "NONE    ", 8);    //CWE144402
          else                                              //CWE144402
          {                                                 //CWE144402
            wk_progress_long = atol(wk_progress_char);      //CWE144402
            //Dont allow a number that will exceed            CWE144402
            //8 digits after multiplying by 1000.             CWE144402
            if (wk_progress_long > 99999)                   //CWE144402
              wk_progress_long = 99999;                     //CWE144402
            wk_progress_long = wk_progress_long * 1000;     //CWE144402
            sprintf(wk_progress_char, "%d",                 //CWE144402
              wk_progress_long);                            //CWE144402
            memcpy(comtopaz->frprogress,                    //CWE144402
              wk_progress_char, 8);                         //CWE144402
          }                                                 //CWE144402
        }                                                   //CWE144402
      }                                                     //CWE144402
      if (diag_ind)                                         //CWE144402
      {                                                     //CWE144402
        memcpy(wk_progress_char, comtopaz->frprogress, 8);  //CWE144402
        fprintf(xfrtrc,                                     //CWE144402
          "\nFRPRGRES Progress interval used    =%s\n",     //CWE144402
          wk_progress_char);                                //CWE144402
      }                                                     //CWE144402

      // get memory to hold z/Unix path name                 //CWE146473
      comtopaz->progress_path = malloc (UNIX_PATH_LENGTH);   //CWE146473
      memset(comtopaz->progress_path,                        //CWE146473
        NULL, UNIX_PATH_LENGTH);                             //CWE146473
      if (xvjopunv->load_module_version >= 4)                //CWE146473
      {                                                      //CWE146473
        memcpy(comtopaz->progress_path,                      //CWE146473
          xvjopunv->tmp_uss_rprt_path,                       //CWE146473
          (UNIX_PATH_LENGTH - 1));                           //CWE146473
      }

      // see if we were sent a request file name, or if we have to
      // go create a request
      // new directions: always call xfrm2ds(), and that code  cwe138631
      // will create the new request file with the proper      cwe138631
      // naming convention                                     cwe138631
      //if (fx_parms->xmlplist->u.fr.fr_reqdsn[0] == ' ')      cwe138631
      //{                                                      cwe138631

      // no request file name, so we're creating one
      //
      // move data into prmm2ds struct and then call XFRM2DS()
      memset (&prmm2ds, 0, sizeof (struct prmm2ds));
      prmm2ds.multiblock = mb_data.buffer;
      prmm2ds.mblength   = fx_parms->xmlplist->mbnbyte;
      //memcpy (prmm2ds.prefix,
      //        fx_parms->xmlplist->u.fr.fr_prefix, 12);
      // HLQ was received as part of init request
      //memcpy (prmm2ds.prefix, wkhlq, strlen (wkhlq));           cwe165302
      // we now get a prefix/suffix that we need to use to        cwe165302
      // to create the request file; use the one we built         cwe165302
      // during the INIT transaction                              cwe165302
      prmm2ds.presuf = presuf;                                  //cwe165302
      memcpy (prmm2ds.workunit, xvjopunv->perm_unit,
              sizeof (xvjopunv->perm_unit));

      // the reqdsn will either be blank, or have a valid     cwe138631
      // request file name; either way, give it to xfrm2ds()  cwe138631
      memcpy (prmm2ds.requestFileName,                      //cwe138631
              prmraf.req->u.fr.fr_reqdsn,                   //cwe138631
              sizeof (prmm2ds.requestFileName));            //cwe138631

      //rc = XFRM2DS (&prmm2ds);
      xfrm2ds (&prmm2ds);

      if (prmm2ds.rc == 0)
      {
        // good request file generation, so move along
        // XFRPOPUL () expects the request ds name here
        memcpy (prmraf.req->u.fr.fr_reqdsn,
                prmm2ds.requestFileName,
                sizeof (prmm2ds.requestFileName));
      }
      else
      {
        // something didn't work
        memset (wkmsg1, 0, sizeof (wkmsg1));
        memset (wkmsg2, 0, sizeof (wkmsg2));
        memset (comgcb->comdvs->rdtch1, ' ',
                sizeof (comgcb->comdvs->rdtch1));
        memcpy (wkmsg1, prmm2ds.message1,
                sizeof (prmm2ds.message1));
        PADNULL (wkmsg1, sizeof (wkmsg1));
        // 2nd msg?
        if (prmm2ds.message2[0] != ' ' &&
            prmm2ds.message2[0] != 0)
        {
          memcpy (wkmsg2, prmm2ds.message2,
                  sizeof (prmm2ds.message2));
          PADNULL (wkmsg2, sizeof (wkmsg2));

          sprintf (comgcb->comdvs->rdtch1, "%s; %s -- Return code: %d",
                   wkmsg1, wkmsg2, prmm2ds.rc);
        }
        else
        {
          sprintf (comgcb->comdvs->rdtch1, "%s -- Return code: %d",
                   wkmsg1, prmm2ds.rc);
        }

        err_dtl.err_code = RDXEE201;
        XFRXENCD (&prmraf);    // Encode the output into XML
        //resp_avail = 0;
        resp_avail = 1;

        //don't terminate until they tell us                    CWE164596
        //loop_status = TERM;                                   CWE164596
        //proc_status = 'X';                                    CWE164596

        xml_ctl = prmraf.vis_raf_out->xml_ctl;
        sd_rcv_prm->srdata = xml_ctl->ioBuffer;
        sd_rcv_prm->srlen = xml_ctl->bufferSize - xml_ctl->bytesRemaining;

        // insure we're not returning multiblock                cwe139919
        sd_rcv_prm->srtrnslt = 'Y';                           //cwe139919

        // display error message, bust out of case                     cwe165302
        if (diag_ind)                                                 //cwe16530
        {                                                             //cwe16530
          time (&wksecs);                                             //cwe16530
          wktime = localtime (&wksecs);                               //cwe16530
          strftime (date_time, 20,"%Y/%m/%d %H:%M:%S", wktime);       //cwe16530
          fprintf (xfrtrc, "\n%s XFRM2DS: failed; prmm2ds.rc = %d",   //cwe16530
                     date_time, prmm2ds.rc);                          //cwe16530
          if (wkmsg1[0] != ' ' && wkmsg1[0] != 0)                     //cwe16530
            fprintf (xfrtrc, "\n%20.20s   msg1 = '%s'", " ", wkmsg1); //cwe16530
          if (wkmsg2[0] != ' ' && wkmsg2[0] != 0)                     //cwe16530
            fprintf (xfrtrc, "\n%20.20s   msg2 = '%s'", " ", wkmsg2); //cwe16530
        }                                                             //cwe16530

        break;
      }

      //}                                                    cwe138631

      // allocate/populate the files needed                       //cwe138369
      rc = XFRPOPUL (comgcb, comtopaz, &prmraf);                  //cwe138369
      if (rc != 0)
      {
        err_dtl.err_code = rc;                                       //CWE107575
        XFRXENCD (&prmraf);    // Encode the output into XML                  D0
        //resp_avail = 0;                                                    //C
        resp_avail = 1;  // a guess

        //loop_status = TERM;                         //CWE101609A  CWE164596
        //proc_status = 'X';                                        CWE164596

        // display error message, bust out of case
        if (diag_ind)
        {
          fprintf (xfrtrc, "\nXFRPOPUL () failed; rc = %d\n", rc);
          // get the extended message
          grc = Geterrmsg (&prmraf);
          if ( grc == 0)
          {
            fprintf (xfrtrc, "  Long Message: '%s'\n",
                     err_dtl.msg_text);
          }
          else
          {
            fprintf (xfrtrc, "  Geterrmsg didn't work : '%d'\n", grc);
          }
        }

        // send message back to workbench
        xml_ctl = prmraf.vis_raf_out->xml_ctl;
        sd_rcv_prm->srdata = xml_ctl->ioBuffer;
        sd_rcv_prm->srlen = xml_ctl->bufferSize - xml_ctl->bytesRemaining;

        // insure we're not returning multiblock          cwe139919
        sd_rcv_prm->srtrnslt = 'Y';                     //cwe139919

        break;
      }

      //and awaaaaaaay we go
      rc = XFRALAT (comtopaz);

      // insure we're not returning multiblock
      sd_rcv_prm->srtrnslt = 'Y';

      if (diag_ind)                                      //cwe137985
      {
        time (&wksecs);                                            //cwe134588
        wktime = localtime (&wksecs);                              //cwe134588
        strftime (date_time, 20,"%Y/%m/%d %H:%M:%S", wktime);      //cwe134588

        fprintf (xfrtrc, "%s XFRRSRVR: after XFRALAT\n", date_time);
        fprintf (xfrtrc, "  rc        : %d\n", rc);
        fprintf (xfrtrc, "  job_status: '%4.4s'\n", comtopaz->job_status);
        fprintf (xfrtrc, "  job_id    : '%8.8s'\n", comtopaz->job_id);
        fprintf (xfrtrc, "  job_name  : '%8.8s'\n", comtopaz->job_name);
        fprintf (xfrtrc, " 1:'%128.128s'\n",                //CWE140500
          comtopaz->IRXEXECB_msg);                          //CWE140500
        fprintf (xfrtrc, " 2:'%128.128s'\n",                //CWE140500
          comtopaz->IRXEXECB_msg[128]);                     //CWE140500
      }                                                     //CWE140500

      if  ((comtopaz->job_status[0] != '0')                 //CWE140500
        && (comtopaz->job_status[1] != 0x00))               //CWE140500
      {                                                     //CWE140500
        err_dtl.err_code = RDXEE436;                        //CWE140500
        memset (comgcb->comdvs->rdtch1, ' ',                //CWE140500   //cwe1
                sizeof (comgcb->comdvs->rdtch1));           //CWE140500   //cwe1
        sprintf (comgcb->comdvs->rdtch1,                    //CWE140500   //cwe1
                 "%s",                                      //CWE140500   //cwe1
                 comtopaz->IRXEXECB_msg);                   //CWE140500   //cwe1
        XFRXENCD (&prmraf);    // Encode the output into XML  CWE140500       D0
        resp_avail = 1;                                     //CWE140500    //CWE
        //loop_status = TERM;     //CWE140500    //CWE101609A CWE164596
        //proc_status = 'X';                     //CWE140500  CWE164596

        if (diag_ind)                                       //CWE140500
          fprintf (xfrtrc,                                  //CWE140500
                   "\nComtopaz job status not zero\n");     //CWE140500

        // send message back to workbench                     CWE140500
        xml_ctl = prmraf.vis_raf_out->xml_ctl;              //CWE140500
        sd_rcv_prm->srdata = xml_ctl->ioBuffer;             //CWE140500
        sd_rcv_prm->srlen =                                 //CWE140500
          xml_ctl->bufferSize - xml_ctl->bytesRemaining;    //CWE140500

        // Insure we're not returning multiblock              CWE140500
        sd_rcv_prm->srtrnslt = 'Y';                         //CWE140500

        break;                                              //CWE140500
      }                                                     //CWE140500

      if (comtopaz->exsreq_rc != 0)                         //CWE141343
      {                                                     //CWE141343
        err_dtl.err_code = comtopaz->exsreq_rc;             //CWE141343
        XFRXENCD (&prmraf);    // Encode the output into XML  CWE141343       D0
        resp_avail = 1;                                     //CWE141343    //CWE
        //loop_status = TERM;               //CWE141343    //CWE101609A      CWE
        //proc_status = 'X';                                //CWE141343      CWE

        if (diag_ind)                                       //CWE141343
          fprintf (xfrtrc,                                  //CWE141343
                   "\nESR returned error = %d\n",           //CWE141343
                   comtopaz->exsreq_rc);                    //CWE141343

        // send message back to workbench                     CWE141343
        xml_ctl = prmraf.vis_raf_out->xml_ctl;              //CWE141343
        sd_rcv_prm->srdata = xml_ctl->ioBuffer;             //CWE141343
        sd_rcv_prm->srlen =                                 //CWE141343
          xml_ctl->bufferSize - xml_ctl->bytesRemaining;    //CWE141343

        // Insure we're not returning multiblock              CWE141343
        sd_rcv_prm->srtrnslt = 'Y';                         //CWE141343

        break;                                              //CWE141343
      }                                                     //CWE141343

      if (rc != 0)
      {
        // bust out of case, display error message
        err_dtl.err_code = rc;                                       //CWE107575
        XFRXENCD (&prmraf);    // Encode the output into XML                  D0
        //resp_avail = 0;                                                    //C
        resp_avail = 1;                                                    //CWE
        //loop_status = TERM;                                   //CWE101609A CWE
        //proc_status = 'X';                                                 CWE

        if (diag_ind)
          fprintf (xfrtrc, "\nXFRALAT() failed\n", rc);

        // send message back to workbench
        xml_ctl = prmraf.vis_raf_out->xml_ctl;
        sd_rcv_prm->srdata = xml_ctl->ioBuffer;
        sd_rcv_prm->srlen = xml_ctl->bufferSize - xml_ctl->bytesRemaining;

        break;
      }

      if (diag_ind)                                      //cwe137985
        fprintf (xfrtrc, "\nXFRRSRVR: calling XFRXENCD with opcode: %d",
                 prmraf.req->u.fr.frreq);                //cwe137985

      // Encode the response                             //cwe137985
      prmraf.metadata = (void *) comtopaz;               //cwe137985
      XFRXENCD (&prmraf);                                //cwe137985
                                                         //cwe137985
      // did that work?                                  //cwe137985
      if (prmraf.rc && diag_ind)                         //cwe137985
        fprintf (xfrtrc,"\nXFRXENCD rc: %d", prmraf.rc); //cwe137985

      if (prmraf.rc == 20)                               //cwe137985
      {                                                  //cwe137985
        if (diag_ind)                                    //cwe137985
          fprintf (xfrtrc,"\nCEASE or DISCONNECT detected by XFRXENCD");

        loop_status = TERM;                              //cwe137985
        proc_status = 'X';                               //cwe137985
        resp_avail  = 0;                                 //cwe137985
        continue;                                        //cwe137985
      }                                                  //cwe137985
                                                         //cwe137985
      if (prmraf.rc == 0)                                //cwe137985
        proc_status = 'D';                               //cwe137985
                                                         //cwe137985
      // Send results to WB                              //cwe137985
      xml_ctl = prmraf.vis_raf_out->xml_ctl;             //cwe137985
      sd_rcv_prm->srdata = xml_ctl->ioBuffer;            //cwe137985
      sd_rcv_prm->srlen = xml_ctl->bufferSize - xml_ctl->bytesRemaining;//CWE101
      resp_avail = 1;                                    //cwe137985
                                                         //cwe137985
      if (diag_ind)                                      //cwe137985
        fprintf (xfrtrc, "\nXFRRSRVR send EXECREQ data response.");     //cwe137

      break;
      //E137442 END

    case 1007: // RETRMETA      request                       CWE141623
      if (diag_ind)                                         //CWE141623
        fprintf (xfrtrc, "\nXFRRSRVR RETRMETA request.");   //CWE141623
      prmraf.req = fx_parms->xmlplist;                      //CWE141623
      memcpy(wk_extr_file_long,                             //CWE141623
             prmraf.req->u.fr.fr_extdsn,                    //CWE141623
             sizeof (prmraf.req->u.fr.fr_extdsn));          //CWE141623
      wk_extr_file_long[56] = NULL;                         //CWE141623
      memset(wk_extr_file, NULL, sizeof(wk_extr_file));     //CWE141623
      memset(wk_extr_mbr,  NULL, sizeof(wk_extr_mbr));      //CWE141623
      lparen = (char *) strchr(wk_extr_file_long, '(');     //CWE141623
      rparen = (char *) strchr(wk_extr_file_long, ')');     //CWE141623
      extr_len = strrspn(wk_extr_file_long, " ");           //CWE141623
      if (lparen)                                           //CWE141623
      {                                                     //CWE141623
        if (rparen > lparen)                                //CWE141623
        {                                                   //CWE141623
          lparen_len = //len of dsn to left paren           //CWE141623
            lparen - (char *) &wk_extr_file_long;           //CWE141623
          if (lparen_len > 44)                              //CWE141623
            lparen_len = 44;                                //CWE141623
          memcpy(wk_extr_file, //move dsn                   //CWE141623
                 wk_extr_file_long, lparen_len);            //CWE141623
          rparen_len = rparen - lparen - 1; //len of member //CWE141623
          if (rparen_len > 8)                               //CWE141623
            rparen_len = 8;                                 //CWE141623
          memcpy(wk_extr_mbr,                               //CWE141623
                 lparen+1, rparen_len); //move member       //CWE141623
        }                                                   //CWE141623
      }     // end of PDS member name handling              //CWE141623
      else                                                  //CWE141623
      {                                                     //CWE141623
        if ((extr_len > 44) || (extr_len < 0))              //CWE141623
          extr_len = 44;                                    //CWE141623
        memcpy(wk_extr_file, wk_extr_file_long, extr_len);  //CWE141623
      }                                                     //CWE141623
      xfrrmeta_buf = (ioBlock_t *)malloc(sizeof(ioBlock_t));//CWE141623
       memset(xfrrmeta_buf, NULL, sizeof(ioBlock_t));       //CWE141623
      rc = err_dtl.err_code = XFRRMETA(comgcb, wk_extr_file,//CWE141623
                                wk_extr_mbr, xfrrmeta_buf,  //CWE141623
                                'N');                       //CWE143153

      if (rc == 20 && diag_ind)                             //CWE141623
        fprintf (xfrtrc, "\nCEASE or DISCONNECT detected by XFRRMETA");

      if (rc == 20)                                         //CWE141623
      {                                                     //CWE141623
        loop_status = TERM;                                 //CWE141623
        proc_status = 'X';                                  //CWE141623
        resp_avail = 0;                                     //CWE141623
        continue;                                           //CWE141623
        // This should have the same effect as goto Abrupt_Shutdown
        // goto Abrupt_Shutdown;
      }
      if (rc != 0)                                          //CWE141623
      {                                                     //CWE141623
        err_dtl.err_code = rc;                              //CWE141623
        XFRXENCD(&prmraf);    // Encode the output into XML   CWE141623
        resp_avail = 1;                                     //CWE141623
        xml_ctl = prmraf.vis_raf_out->xml_ctl;              //CWE141623
        sd_rcv_prm->srdata = xml_ctl->ioBuffer;             //CWE141623
        sd_rcv_prm->srlen =                                 //CWE141623
          xml_ctl->bufferSize - xml_ctl->bytesRemaining;    //CWE141623
      }                                                     //CWE141623
      // Send results to WB
      xml_ctl = xfrrmeta_buf;                               //CWE141623
      if (rc == 0 && xml_ctl && xml_ctl->ioBuffer)          //CWE141623
      {
        resp_avail = 1; //The output should be in XML buffer  CWE141623
        proc_status = 'D';                                  //CWE141623
        sd_rcv_prm->srdata = xml_ctl->ioBuffer;             //CWE141623
        sd_rcv_prm->srlen =                                 //CWE141623
          xml_ctl->bufferSize - xml_ctl->bytesRemaining;    //CWE141623
        if (diag_ind)                                       //CWE141623
          fprintf (xfrtrc,                                  //CWE141623
            "\nXFRRSRVR send RETRMETA data response.");     //CWE141623

      }
      break;                                                //CWE141623

    case 1008: // GET META LIST
    case 1009: // VER TABLE LIST
      if (diag_ind)
      {
        time (&wksecs);
        wktime = localtime (&wksecs);
        strftime (date_time, 20,"%Y/%m/%d %H:%M:%S", wktime);
        fprintf (xfrtrc, "\n%s XFRRSRVR: Received VER TAB/BLD META request",
                          date_time);
        fprintf (xfrtrc, "\n%20.20s  FRFTCHCT - %d   DDL OPTION - %c",
                         " ", xmlplist->u.fr.fr_fetch_cnt,
                              xmlplist->u.fr.fr_ddl_opt);   //cwe156376
      }

      // connect to the subsystem - moved down                CWE152293

      //if (rc == 0)                        cwe149470
      // rc of 4 is all right               cwe149470
//    if (rc == 0 || rc == 4)             //cwe149470         CWE152293
//    {                                                       CWE152293
        // build the creator/table, mvs layout/01 level list  CWE152293
//      rc = bldcrtb (xmlplist, &mb_data, &prmtbmet);       //CWE152293
      db2_flag_1008_1009 = 'N';                             //CWE152293
      rc = bldobjtab (xmlplist, &mb_data,                   //CWE152293
                      &prmtbmet, &db2_flag_1008_1009);      //CWE152293

      if (diag_ind)
      {
        // dump the creators/tables
//      dmptbcr (&prmtbmet);                                  CWE152293
        dmpobjtbl (&prmtbmet);                              //CWE152293
      }

      if (db2_flag_1008_1009 == 'Y')                        //CWE152293
      {                                                     //CWE152293
        // connect to the subsystem                           CWE152293
        memcpy (ssid, fx_parms->xmlplist->u.fr.fr_ssid, 4); //CWE152293

        prmraf.req = fx_parms->xmlplist;                    //CWE152293
        err_dtl.err_code = XFRHCONN (comgcb, ssid);         //CWE152293
        rc = err_dtl.err_code;                              //CWE152293
        if (diag_ind)                                       //CWE152293
        {                                                   //CWE152293
          time (&wksecs);                                   //CWE152293
          wktime = localtime (&wksecs);                     //CWE152293
          strftime (date_time, 20,                          //CWE152293
            "%Y/%m/%d %H:%M:%S", wktime);                   //CWE152293
          fprintf (xfrtrc, "\n%s XFRHCONN rc: %d",          //CWE152293
            date_time, rc);                                 //CWE152293
        }                                                   //CWE152293
      }                                                     //CWE152293

      //if (rc == 0)                        cwe149470
      // rc of 4 is all right               cwe149470
      if (rc == 0 || rc == 4)             //cwe149470
      {

        if (rc == 0)
        {
          // build METALIST, or verify tables
          prmtbmet.opcode = req_code;
          prmtbmet.comgcb = comgcb;

          // pass ddl option to TBMET                        cwe156376
          prmtbmet.ddlflag = xmlplist->u.fr.fr_ddl_opt;    //cwe156376

          // XFRTBMET (&prmtbmet);                  cwe149121
          // we oughta check the return code        cwe149121
          rc = XFRTBMET (&prmtbmet);              //cwe149121

          if (diag_ind)
          {
            // dump the results
            dmptbmeta (&prmtbmet);
          }

          if (rc == 0)
          {
            // prepare success response
            sd_rcv_prm->srdata = prmtbmet.retstr;
            sd_rcv_prm->srlen  = strlen (prmtbmet.retstr);
          }
          else
          {                                        //cwe149121
            if (diag_ind)                          //cwe149121
            {                                      //cwe149121
              time (&wksecs);                      //cwe149121
              wktime = localtime (&wksecs);        //cwe149121
              strftime (date_time, 20,"%Y/%m/%d %H:%M:%S", wktime);
              fprintf (xfrtrc, "\n%s XFRTBMET failed rc: %d", date_time, rc);
            }

            err_dtl.err_code = rc;                       //cwe149121
            XFRXENCD (&prmraf);                          //cwe149121
            xml_ctl = prmraf.vis_raf_out->xml_ctl;       //cwe149121
            sd_rcv_prm->srdata = xml_ctl->ioBuffer;      //cwe149121
            sd_rcv_prm->srlen = xml_ctl->bufferSize - xml_ctl->bytesRemaining; /
          }                                              //cwe149121

          resp_avail = 1;                                             //CWE10160
          // insure we're not returning multiblock
          sd_rcv_prm->srtrnslt = 'Y';
        }
      }
      else
      {
        // XFRXENCD() handles the error message
        XFRXENCD (&prmraf);    // Encode the output into XML               //CWE

        // did that work?
        if (prmraf.rc && diag_ind)                                   //cwe134588
        {
          fprintf (xfrtrc,"\nXFRXENCD rc: %d", prmraf.rc);                   //c
          fflush (xfrtrc);
        }

        if (prmraf.rc == 20 && diag_ind)                                  //CWE1
          fprintf (xfrtrc,"\nCEASE or DISCONNECT detected by XFRXENCD");  //cwe1

        if (prmraf.rc == 20)                                              //CWE1
        {                                                             //CWE10160
          loop_status = TERM;                                         //CWE10160
          proc_status = 'X';                                          //CWE10160
          resp_avail = 0;                                             //CWE10160
          continue;                                                   //CWE10160
        }                                                             //CWE10160

        if (prmraf.rc == 0)                                               //CWE1
          proc_status = 'D';                                              //CWE1

        // Send results to WB                                             //CWE1
        xml_ctl = prmraf.vis_raf_out->xml_ctl;                            //CWE1
        sd_rcv_prm->srdata = xml_ctl->ioBuffer;                           //CWE1
        sd_rcv_prm->srlen = xml_ctl->bufferSize - xml_ctl->bytesRemaining;//CWE1
        resp_avail = 1;                                                   //CWE1
        sd_rcv_prm->srtrnslt = 'Y';

        if (diag_ind)                                                     //CWE1
        {
          fprintf (xfrtrc, "\nXFRRSRVR trans '%d' data response.", req_code);
          fflush (xfrtrc);
        }

      }
      break;

    case 1010: // Get rel thread for relationship import     //CWE152660
      if (diag_ind)                                          //CWE152660
        fprintf (xfrtrc, "\nXFRRSRVR REL IMPORT request.");  //CWE152660/cwe1345

      memset(&prmrlimp, NULL, sizeof(struct prmrlimp));      //CWE152660
      prmrlimp.xmlplist = xmlplist;                          //CWE152660
      prmrlimp.comgcb   = comgcb;                            //CWE152660
      xfrrlimp(&prmrlimp);     // build thread & meta data   //CWE152660

      if (prmrlimp.err_code == 0)                            //CWE152660
      {                                                      //CWE152660
        xml_ctl = prmrlimp.xml_ctl;                          //CWE152660
        sd_rcv_prm->srdata = xml_ctl->ioBuffer;              //CWE152660
        sd_rcv_prm->srlen = xml_ctl->bufferSize - xml_ctl->bytesRemaining;  //CW
      }                                                      //CWE152660
      else                                                   //CWE152660
      {                                                      //CWE152660
        if (diag_ind)                                        //CWE152660
        {                                                    //CWE152660
          time(&wksecs);                                     //CWE152660
          wktime = localtime(&wksecs);                       //CWE152660
          strftime(date_time, 20,"%Y/%m/%d %H:%M:%S", wktime); //CWE152660
          fprintf(xfrtrc, "\n%s XFRRLIMP failed rc: %d",     //CWE152660
                 date_time, prmrlimp.err_code);              //CWE152660
        }                                                    //CWE152660

        err_dtl.err_code = prmrlimp.err_code;                //CWE152660
        XFRXENCD(&prmraf);                                   //CWE152660
        xml_ctl = prmraf.vis_raf_out->xml_ctl;               //CWE152660
        sd_rcv_prm->srdata = xml_ctl->ioBuffer;              //CWE152660
        sd_rcv_prm->srlen = xml_ctl->bufferSize - xml_ctl->bytesRemaining; //CWE
      }                                                      //CWE152660

      resp_avail = 1;                                        //CWE152660
      proc_status = 'D';                                     //CWE152660
      break;                                                 //CWE152660

    case 1011: // GETRIRELM - get ri for multiple tables       cwe155431
               // entire case added for cwe155431, not tagging each line
      if (diag_ind)
      {
        fprintf (xfrtrc, "\n%s GETRIRELM entry\n", __FILE__);
        // dump the ri_load data
        // need to test
        //prrildinfo (prmraf.req);
      }

      prmraf.req = fx_parms->xmlplist;
      memcpy (ssid, prmraf.req->u.fr.fr_ssid, 4);

      err_dtl.err_code = XFRHCONN (comgcb, ssid);
      rc = err_dtl.err_code;
      if (diag_ind)
      {
        time (&wksecs);
        wktime = localtime (&wksecs);
        strftime (date_time, 20,"%Y/%m/%d %H:%M:%S", wktime);
        fprintf (xfrtrc, "\n%s XFRHCONN rc: %d, ssid: '%4.4s'",
                          date_time, rc, ssid);
      }

      if (rc == 0 || rc == 4)
      {
        // go parse cre/tab pairs from multi-block
        rc = bldobjtab (xmlplist, &mb_data, &prmtbmet, &db2_flag_1008_1009);

        if (diag_ind)
          dmpobjtbl (&prmtbmet);

        // loop through each creator/table pair,
        for (tbptr = prmtbmet.tab_list;
             tbptr != NULL;
             tbptr = tbptr->next)
        {
          // see if we already have the cre/tbn in the list of rels
          if (relhead != NULL)
          {
            rc = scanrels (relhead, tbptr);
            if (rc != 0)
              continue;
          }

          // move the cre/tbn into the xmlplist, converting to
          // hex (the xmlplist cre/tbn must be in hex)
          hexlen = Convert_to_Hex (xmlplist->u.fr.fr_creator,
                                   tbptr->db2.creator,
                                   CRTR_NAME_LGTH);
          PADSPACE (xmlplist->u.fr.fr_creator,
                    sizeof (xmlplist->u.fr.fr_creator));

          hexlen = Convert_to_Hex (xmlplist->u.fr.fr_tbname,
                                   tbptr->db2.tbname,
                                   CRTR_NAME_LGTH);
          PADSPACE (xmlplist->u.fr.fr_tbname,
                    sizeof (xmlplist->u.fr.fr_tbname));

          // go get rels from catalog; build it's metadata
          XFRRIDAT (&prmraf);

          if (diag_ind)                                                     //cw
            fprintf (xfrtrc,"\nXFRRIDAT rc: %d\n", prmraf.rc);                //

          if (prmraf.rc == 20 && diag_ind)                                    //
            fprintf (xfrtrc,"\nCEASE or DISCONNECT detected by XFRRIDAT");   //c

          if (rc == 20)                                                  //CWE10
          {                                                             //CWE101
            loop_status = TERM;                                         //CWE101
            proc_status = 'X';                                          //CWE101
            resp_avail = 0;                                             //CWE101
            continue;                                                   //CWE101
          }                                                             //CWE101

          if (relhead == NULL)
          {
            // have any rels to add?
            if (prmraf.vis_raf_out->first_rel->rel != NULL)
              relhead = prmraf.vis_raf_out->first_rel;
          }
          else
          {
            // have any rels to add?
            if (prmraf.vis_raf_out->first_rel->rel != NULL)
              addrele (relhead, prmraf.vis_raf_out->first_rel->rel);
          }

        }  // end of for (tbptr = prmtbmet.tab_list ...

      }

      if (diag_ind)
      {
        // dump rel llist
        dmprelhd (relhead);
      }

      // attach the rel llist to the Rel_Sel
      prmraf.vis_raf_out->first_rel = relhead;

      XFRXENCD (&prmraf);    // Encode the output into XML               //CWE10

      // did that work?
      if (prmraf.rc && diag_ind)                                   //cwe134588
      {
        fprintf (xfrtrc,"\nXFRXENCD rc: %d", prmraf.rc);                   //cwe
        fflush (xfrtrc);
      }

      if (prmraf.rc == 20 && diag_ind)                                  //CWE101
        fprintf (xfrtrc,"\nCEASE or DISCONNECT detected by XFRXENCD");  //cwe134

      if (prmraf.rc == 20)                                              //CWE101
      {                                                             //CWE101609A
        loop_status = TERM;                                         //CWE101609A
        proc_status = 'X';                                          //CWE101609A
        resp_avail = 0;                                             //CWE101609A
        continue;                                                   //CWE101609A
        // This should have the same effect as goto Abrupt_Shutdown //CWE101609A
        // goto Abrupt_Shutdown;                                    //CWE101609A
      }                                                             //CWE101609A

      if (prmraf.rc == 0)                                               //CWE101
        proc_status = 'D';                                              //CWE101

      // Send results to WB                                             //CWE101
      xml_ctl = prmraf.vis_raf_out->xml_ctl;                            //CWE101
      sd_rcv_prm->srdata = xml_ctl->ioBuffer;                           //CWE101
      sd_rcv_prm->srlen = xml_ctl->bufferSize - xml_ctl->bytesRemaining;//CWE101
      resp_avail = 1;                                                   //CWE101

      // this is getting screwed up somehow
      sd_rcv_prm->srtrnsmt = 0;
      sd_rcv_prm->srtrnslt = 'Y';

      if (diag_ind)                                                     //CWE101
      {
        fprintf (xfrtrc, "\nXFRRSRVR send GETRIRELM data response.\n");    //cwe

        fprintf (xfrtrc, "\n      struct prmsdrcv contents:");
        fprintf (xfrtrc, "\n              char *srdata   %p", sd_rcv_prm->srdata
        fprintf (xfrtrc, "\n              char *srxib    %p", sd_rcv_prm->srxib
        fprintf (xfrtrc, "\n               int  srlen    %d", sd_rcv_prm->srlen
        fprintf (xfrtrc, "\n               int  srtrnsmt %d", sd_rcv_prm->srtrns
        fprintf (xfrtrc, "\n              char  srtrnslt %c", sd_rcv_prm->srtrns
        fprintf (xfrtrc, "\n              char  srlast   %c", sd_rcv_prm->srlast
        fprintf (xfrtrc, "\n              char  sr64bit  %c", sd_rcv_prm->sr64bi
      }

      break;                                                            //CWE101

    case 1012: // GETDSATT - get ds attributes for multiple datasets     cwe1586

      if (diag_ind)
      {
        time (&wksecs);
        wktime = localtime (&wksecs);
        strftime (date_time, 20,"%Y/%m/%d %H:%M:%S", wktime);
        fprintf (xfrtrc, "\n%s XFRRSRVR: GETDSATT entry", date_time);
        fprintf (xfrtrc, "\n%20.20s  FRFTCHCT - %d",
                         " ", xmlplist->u.fr.fr_fetch_cnt);
      }

      // we only do version 2 of the multiblock input
      // since we're only dealing with MVS stuff
      xmlplist->xmlvrsn = 2;

      memset (&prmtbmet, 0, sizeof (prmtbmet));
      rc = bldobjtab (xmlplist, &mb_data,
                      &prmtbmet, &db2_flag_1008_1009);

      if (diag_ind)
      {
        // dump the ds names
        dmpobjtbl (&prmtbmet);
      }

      // go build the list of dsatt struct

      for (currtb = prmtbmet.tab_list, currdslst = dslsthead;
           currtb != NULL;
           currtb = currtb->next)
      {
        // call fileaid getting the attributes
        comgcb->comfavt->frdsfunc = FADSATT + FAVERIFY;
        *comgcb->comreli->parent_xref->def.layout_rec = ' ';
        comgcb->comfavt->frfareq  = 'P';
        facall_FP = comgcb->comsubvt->addr_FACALL;    //cwe158646
        memset (workstr, 0, sizeof (workstr));
        sprintf (workstr, "'%s'", currtb->mvs.layout_dsn);

        // get the attributes, as well as verify the dataset
        memset (comgcb->comreli->FRINQKY1, ' ',
                sizeof (comgcb->comreli->FRINQKY1));
        memcpy (comgcb->comreli->FRINQKY1, workstr,
                strlen (workstr));

        rc = facall_FP(comgcb);
        if (rc == 0)
        {
          // got a dsdatt, so tack this onto the list
          if ( currdslst == NULL )
          {
            dslsthead = (struct dsattlst *) malloc (sizeof (struct dsattlst));
            memset (dslsthead, 0, sizeof (struct dsattlst));
            currdslst = dslsthead;
            dslsthead->dsatt = (struct comdsatt *) comgcb->comfavt->dsattptr;
            currdslst->dsatt = dslsthead->dsatt;
          }
          else
          {
            currdslst->next = (struct dsattlst *) malloc (sizeof (struct dsattls
            memset (currdslst->next, 0, sizeof (struct dsattlst));
            currdslst = currdslst->next;
            (struct comdsatt *) comgcb->comfavt->dsattptr;
            currdslst->dsatt = (struct comdsatt *) comgcb->comfavt->dsattptr;
          }
        }
        else
        {
          // something went wrong with facall_FP()
          if (facall_err == 0)
          {
            facall_err = rc;
            memset (errdsn, 0, sizeof (errdsn));
            memcpy (errdsn, workstr, strlen (workstr));
          }
        }
      }

      if (dslsthead != NULL)
      {
        // go build the xml
        prmraf.req = fx_parms->xmlplist;
        prmraf.dsattlst = dslsthead;

        XFRXENCD (&prmraf);

        // free the dsatt chain
        for (currdslst = dslsthead;;)
        {
          nextdslst = currdslst->next;
          DSAFREE (currdslst->dsatt);
          if (nextdslst == NULL)
          {
            currdslst = NULL;
            break;
          }
          else
            currdslst = nextdslst;
        }
      }
      else
      {
        // we got no DSATT structs

        //loop_status = TERM;
        //proc_status = 'X';
        //resp_avail = 0;

        if (diag_ind)
        {
          time(&wksecs);
          wktime = localtime(&wksecs);
          strftime (date_time, 20,"%Y/%m/%d %H:%M:%S", wktime);
          fprintf (xfrtrc, "\n%s facall() returned no DSATTs", date_time);
          fprintf (xfrtrc, "\n%20.20sFirst DSN: %s, facall() error: %d",
                   " ", errdsn, facall_err);
        }

        prmraf.err_dtl->err_code = RDXE099;
        memset (comgcb->comdvs->rdtch1, ' ',
                sizeof (comgcb->comdvs->rdtch1));
        strcpy (comgcb->comdvs->rdtch1, errdsn);

        XFRXENCD (&prmraf);
        xml_ctl = prmraf.vis_raf_out->xml_ctl;
        sd_rcv_prm->srdata = xml_ctl->ioBuffer;
        sd_rcv_prm->srlen  = xml_ctl->bufferSize - xml_ctl->bytesRemaining;
      }


      if (diag_ind)
      {
        // did XFRXENCD work?
        if (prmraf.rc)
          fprintf (xfrtrc,"\n%20.20sXFRXENCD rc: %d", " ", prmraf.rc);

        if (prmraf.rc == 20)
          fprintf (xfrtrc,"\n%20.20sCEASE or DISCONNECT detected by XFRXENCD", "
      }

      if (prmraf.rc == 20)
      {
        loop_status = TERM;
        proc_status = 'X';
        resp_avail = 0;
        continue;
      }

      if (prmraf.rc == 0)
        proc_status = 'D';

      // if we get here, all is well, so send results to WB
      xml_ctl = prmraf.vis_raf_out->xml_ctl;
      resp_avail = 1;
      sd_rcv_prm->srdata = xml_ctl->ioBuffer;
      sd_rcv_prm->srlen = xml_ctl->bufferSize - xml_ctl->bytesRemaining;
      sd_rcv_prm->srtrnsmt = 0;
      sd_rcv_prm->srtrnslt = 'Y';

      break;

    default:   // unknown request                                       //CWE101
#define UNKNOWN_REQ -7430  //RDXEE430                                   //CWE101
      prmraf.err_dtl->err_code = UNKNOWN_REQ;                           //CWE101
      XFRXENCD(&prmraf);                                                //CWE101
      resp_avail = 1;                                                   //CWE101
      xml_ctl = prmraf.vis_raf_out->xml_ctl;                            //CWE101
      sd_rcv_prm->srdata = xml_ctl->ioBuffer;                           //CWE101
      sd_rcv_prm->srlen = xml_ctl->bufferSize - xml_ctl->bytesRemaining;//CWE101

    } // End of switch (req_code)

    //Normal_Output:
    if (diag_ind)
      fprintf (xfrtrc, "\n%20.20sXFRRSRVR resp_avail: %d\n", " ", resp_avail);

    if (resp_avail)
    {
      if (diag_ind)
      {
        int  wrk_len;
        char wrk_str[241];

        fprintf (xfrtrc, "\nXFRRSRVR send response.");                   //cwe13
        fprintf (xfrtrc, "\n  XML resp len = %d.", sd_rcv_prm->srlen);   //cwe13

        wrk_len = sd_rcv_prm->srlen;
        if (wrk_len > 240)
          wrk_len = 240;
        memcpy(wrk_str, sd_rcv_prm->srdata, wrk_len);
        wrk_str[wrk_len] = '\0';
        fprintf (xfrtrc, "\n  First portion...\n%s", wrk_str);            //cwe1
      }

      if (proc_status == 'T')
        sd_rcv_prm->srlast = 'Y';

      // now post that we have data to send
      *fx_parms->ecb_sdrcv = 0;
      CWASMSRV(&op_post, &reg1, fx_parms->ecb_func_compl, &send_func);
      CWASMSRV(&op_wait_1, &reg1, fx_parms->ecb_sdrcv);
#define SENDDONE 1
      fx_parms->prmsrvcs->srstat = fx_parms->prmsrvcs->srstat | SENDDONE;
      resp_avail = 0;

      //These free's have to be done after the response is    CWE141623
      //sent and after diagnostic printing, if any.  If they  CWE141623
      //are done at the end of the 1007 case the              CWE141623
      //xfrrmeta_buf->ioBuffer is immediately zeroed out (at  CWE141623
      //least in-house) and the 'First portion' fprintf above CWE141623
      //prints nothing.                                       CWE141623
      if (req_code == 1007)                                 //CWE141623
      {                                                     //CWE141623
        if ((xfrrmeta_buf) && (xfrrmeta_buf->ioBuffer))     //CWE141623
        {                                                   //CWE141623
          free(xfrrmeta_buf->ioBuffer);                     //CWE141623
        }                                                   //CWE141623
        if (xfrrmeta_buf)                                   //CWE141623
        {                                                   //CWE141623
          free(xfrrmeta_buf);                               //CWE141623
          xfrrmeta_buf = NULL;                              //CWE141623
        }                                                   //CWE141623
      }                                                     //CWE141623
    }

    if (diag_ind)
    {
      fprintf (xfrtrc, "\nXFRRSRVR receive next request.");        //cwe134588

      // did we get a term request?
      if (req_code == 2 && xfrtrc != NULL)
      {
        // last message, close file
        time (&wksecs);                                            //cwe134588
        wktime = localtime (&wksecs);                              //cwe134588
        strftime (date_time, 20,"%Y/%m/%d %H:%M:%S", wktime);      //cwe134588

        fclose (xfrtrc);
        xfrtrc = NULL;
      }
    }

    //
    //if (diag_ind)
    //{
    //  // on occasion, we lose some trace data because of an abend
    //  // so during development, if we close and re-open the trace file
    //  // we can retain many of the diag messages
    //  //
    //  // this can be kinda expensive, cause closing/reopening a file
    //  // can be time consuming. but ... so is tracing, anyway
    //  time (&wksecs);                                            //cwe134588
    //  wktime = localtime (&wksecs);                              //cwe134588
    //  strftime (date_time, 20,"%Y/%m/%d %H:%M:%S", wktime);      //cwe134588
    //
    //  fprintf (xfrtrc, "\n%s: close and then reopen the trace file.", date_tim
    //
    //  fclose (xfrtrc);
    //  xfrtrc = fopen (trcdsn, "a");
    //  time (&wksecs);                                            //cwe134588
    //  wktime = localtime (&wksecs);                              //cwe134588
    //  strftime (date_time, 20,"%Y/%m/%d %H:%M:%S", wktime);      //cwe134588
    //  fprintf (xfrtrc, "\n%s: reopening.", date_time);
    //}

    // Now wait for next incoming request
    *fx_parms->ecb_wake_up = 0;
    sd_rcv_prm->srtrnsmt = 2;                          // recv ? transmissions
    sd_rcv_prm->srlen = fx_buffer_len;                  //
    CWASMSRV(&op_post, &reg1, fx_parms->ecb_func_compl, &skip_snd_rcv);
    CWASMSRV(&op_wait_1, &reg1, fx_parms->ecb_wake_up);
    fx_buffer_len = *fx_parms->tpx_bufln;
    xfr_flag = *fx_parms->xfr_flag;

#define FORCEEND 8
#define SHUTDOWN 4
    if (xfr_flag & FORCEEND+SHUTDOWN)
    {
      proc_status = 'T';
      loop_status = 'T';
      if (xfr_flag & SHUTDOWN)
      {
        if (diag_ind)
        {
          // get time/date into strings we can use                   //cwe134588
          time (&wksecs);                                            //cwe134588
          wktime = localtime (&wksecs);                              //cwe134588
          strftime (date_time, 20,"%Y/%m/%d %H:%M:%S", wktime);      //cwe134588

          fprintf (xfrtrc, "\n%s: Received HCI shutdown notification.",
                   date_time);     //cwe134588
          fprintf (xfrtrc, "\n                 -- xfr_flag = '0x%x'\n", xfr_flag
        }
        // Set variables in msg_dtl for explanation
        //   Probably do NOT want to send such a message - WB should already be
        //   if this is a normal shutdown.
        //
        memcpy(wto_msg, "CXFAXFR004W HCI SHUTDOWN NOTIFICATION RECEIVED.", 47);/
        WTO(wto_msg);                                                          /
        //err_dtl.err_code = -7409;  // HCI shutdown notification       D0016408
        err_dtl.err_code = RDXEE409;                               //CWE107575
        XFRXENCD(&prmraf);    // Encode the output into XML
        xml_ctl = prmraf.vis_raf_out->xml_ctl;
        sd_rcv_prm->srdata = xml_ctl->ioBuffer;
        sd_rcv_prm->srlen = xml_ctl->bufferSize - xml_ctl->bytesRemaining;
      }
      else
      {
        if (diag_ind)
        {
          // get time/date into strings we can use                   //cwe134588
          time (&wksecs);                                            //cwe134588
          wktime = localtime (&wksecs);                              //cwe134588
          strftime (date_time, 20,"%Y/%m/%d %H:%M:%S", wktime);      //cwe134588
          fprintf (xfrtrc, "\n%s: Forced Ending by FXSERVER. Check for invalid/u
                   date_time);     //cwe134588
          fprintf (xfrtrc, "\n                    xfr_flag = '0x%x'\n", xfr_flag
        }

        memcpy(wto_msg, "CXFAXFR003S FORCED END BY FXSERVER.", 35);           //
        WTO(wto_msg);                                                         //
        //err_dtl.err_code = -7410;  // HCI forced shutdown             D0016408
        err_dtl.err_code = RDXEE410;                               //CWE107575
        XFRXENCD(&prmraf);    // Encode the output into XML
        xml_ctl = prmraf.vis_raf_out->xml_ctl;
        sd_rcv_prm->srdata = xml_ctl->ioBuffer;
        sd_rcv_prm->srlen = xml_ctl->bufferSize - xml_ctl->bytesRemaining;
      }
    }
  } // End of normal processing loop (loop_status for loop)

  if (diag_ind)
  {
    // get time/date into strings we can use                   //cwe134588
    time (&wksecs);                                            //cwe134588
    wktime = localtime (&wksecs);                              //cwe134588
    strftime (date_time, 20,"%Y/%m/%d %H:%M:%S", wktime);      //cwe134588
    fprintf (xfrtrc, "\n%s XFRRSRVR: outside of main loop\n",
             date_time);            //cwe134588
  }

  //FORCE_EXIT:
  if (proc_status == 'A' || proc_status == 'T')
  {
    if (diag_ind)
    {
      // dump time stamp, close tracefile
      time (&wksecs);
      wktime = localtime (&wksecs);
      strftime (date_time, 20,"%Y/%m/%d %H:%M:%S", wktime);
      fprintf (xfrtrc, "\n%s: Termination sent to WB; proc_status - %c\n",
               date_time, proc_status);
      fclose (xfrtrc);
    }

    memset(sd_rcv_prm, '\0', sizeof(struct prmsdrcv));
    sd_rcv_prm->srxib = fx_parms->tpx_in_buf;
    sd_rcv_prm->srlast = 'N';
    sd_rcv_prm->srtrnslt = 'Y';
    xml_ctl = prmraf.vis_raf_out->xml_ctl;
    sd_rcv_prm->srdata = xml_ctl->ioBuffer;
    sd_rcv_prm->srlen = xml_ctl->bufferSize - xml_ctl->bytesRemaining;
    *fx_parms->ecb_sdrcv = 0;
    CWASMSRV(&op_post, &reg1, fx_parms->ecb_func_compl, &send_func);
    CWASMSRV(&op_wait_1, &reg1, fx_parms->ecb_sdrcv);
    fx_parms->prmsrvcs->srstat = fx_parms->prmsrvcs->srstat | SENDDONE;

    if (proc_status == 'A')
    {
      *(fx_parms->xfr_flag) = *(fx_parms->xfr_flag) | FRABEND;
      memcpy(wto_msg, "CXFAXFR003S ABEND DETECTED.", 26);                 //D001
      WTO(wto_msg);                                                       //D001
    }

    *fx_parms->ecb_wake_up = 0;
    CWASMSRV(&op_post, &reg1, fx_parms->ecb_func_compl, &skip_snd_rcv);
    CWASMSRV(&op_wait_1, &reg1, fx_parms->ecb_wake_up);
  }

  //Abrupt_Shutdown:                                         //d0017216
  if (diag_ind)
  {
    // get time/date into strings we can use                   //cwe134588
    time (&wksecs);                                            //cwe134588
    wktime = localtime (&wksecs);                              //cwe134588
    strftime (date_time, 20,"%Y/%m/%d %H:%M:%S", wktime);      //cwe134588

    if (tpxib->tpxfl3 & 0x01)
    {
      fprintf (xfrtrc, "\n             CEASE received.");                  //cwe
      fprintf (xfrtrc, "\n             CXFAXFR001W CEASE REQUEST DETECTED.");
    }
    if (tpxib->tpdsa->tpfl1 & 0x10)
    {
      fprintf (xfrtrc, "\n             Disconnect indication received.");  //cwe
      fprintf (xfrtrc, "\n             CXFAXFR001W DISCONNECT DETECTED.");
    }

    fprintf (xfrtrc, "\n%s XFRRSRVR: TERM request received.\n", //cwe134588
             date_time);                                        //cwe134588

    fprintf (xfrtrc, "\n%s XFRRSRVR: Closing trace file.\n", //cwe134588
             date_time);                                        //cwe134588

    fclose (xfrtrc);                                   //cwe134588
    xfrtrc = NULL;
  }

  if (tpxib->tpxfl3 & 0x01)                                               //D001
  {                                                                       //D001
    memcpy(wto_msg, "CXFAXFR001W CEASE REQUEST DETECTED.", 35);           //D001
    WTO(wto_msg);                                                         //D001
  }                                                                       //D001

  if (tpxib->tpdsa->tpfl1 & 0x10)                                         //D001
  {                                                                       //D001
    memcpy(wto_msg, "CXFAXFR001W DISCONNECT DETECTED.", 32);              //D001
    WTO(wto_msg);                                                         //D001
  }
                                                                        //D00172
  Cleanup(fx_parms, &prmraf);
  //if (proc_status == 'A')
  //{ // Tell FXSERVER that we are done.
  //  CWASMSRV(&op_post, &reg1, fx_parms->ecb_func_compl, &skip_snd_rcv);
  //} // Tell FXSERVER that we are done.

  //CEEHDLU(&cee_rtn, &fc); // Unregister Abend_Reporter

  // did we get a term request?
  //if (diag_ind == 1 && req_code == 2 && xfrtrc != NULL)
  //{
  //  // Done, so close the file
  //  fclose (xfrtrc);
  //  xfrtrc = NULL;
  //}

  // memory dump code (temp)
  //FrMemDmpFP();
  //fclose(comgcb->mem_log_file);


  return;
}

static void
Cleanup(struct FXSERV_Parms *fx_parms, struct PrmRAF *prmraf)
{
  // The FXSERV_Parms area needs to be freed.
  free(fx_parms);
  // The data anchored in PrmRAF must be freed.
  // clear the lists of output objects
  // clear the lists of ssid's, creators, HLQ's
  // clear the binary search trees

  return;
}


// Get_Parms populates an FXSERV_Parms struct with addresses.
// The addresses are the 10 arguments sent to the main routine
// on the command line.
// Get_Parms does this by converting each string numeric argument
// into an address and assiging the next variable in the
// the FXSERV_Parms struct to that address.
//
// for example, if XFRRSRVR was called like this:
//
// XFRRSRVR 002F55D0 0001FD40 07D27640 ...
//
// then upon return from this function was called, the fx_parms elements
// would be like this:
//
// fx_parms->prmsrvcs = 002F55D0
// fx_parms->ecb_func_compl = 0001FD40
// fx_parms->ecb_wake_up = 07D27640
// ...
//
// in case anyone ever needs/wants to know which args go into
// which pointer, here's the FXSERV_Parms struct:
//
//struct FXSERV_Parms
//{
//  struct prmsrvcs  *prmsrvcs;            // addr of prmsrvcs (in FXSERVER)
//  int              *ecb_func_compl;      // addr of ECB for signalling I am co
//  int              *ecb_wake_up;         // addr of ECB to wake me up
//  char             *xfr_flag;            // addr of FRFLAG (major signal flag)
//  char             *tpx_out_buf;         // addr of output buffer
//  int              *tpx_bufsz;           // addr of buffer size (length of dat
//  int              *tpx_bufln;           // addr of buffer length (length of r
//  struct prmsdrcv  *prm_sdrcv;           // addr of parameters for send/receiv
//  int              *ecb_sdrcv;           // addr of ECB for send/receive
//  char             *tpx_dsn_hlq;         // addr of DSN high level qualifier
//  char             *tpx_in_buf;          // addr of input buffer
//  struct xmlplist  *xmlplist;            // addr of parsed XML
//};
//
static void
Get_Parms(struct FXSERV_Parms *fx_parms, int argc, char **argv)
{
  short             prm_num;
  char              wrk_hex_str[16];
  void             *wrk_addr;
  void            **prm_addr;
  struct prmsrvcs  *prmsrvcs;

  if (argc < 11)
    return;
  prm_addr = (void **)&(fx_parms->prmsrvcs);
  for (prm_num = 1; prm_num <= 10; prm_num++)
  {
    memcpy(wrk_hex_str, argv[prm_num], 8);
    wrk_hex_str[8] = '\0';
    sscanf(wrk_hex_str, "%p", &wrk_addr);
    *prm_addr = wrk_addr;
    prm_addr++;
  }
  prmsrvcs = fx_parms->prmsrvcs;
  fx_parms->xmlplist = prmsrvcs->ptrplist;
  fx_parms->tpx_in_buf = prmsrvcs->ptrxib;
  return;
}

// ------------ Abnd_Exit ------------
// Signal/abend handler routine
// This routine uses standard C entry and
//   exit for handling errors and reporting.
// It uses IBM CEE reporting routines, but
// does NOT use CEE handler routines due to
// those routines not supporting C WSA areas.
// Also, this routine calls "Find_LM" to
// determine what load module the error was in.
// When this routine is done, a "longjump" is
// made that will result in an RDX msg retrieval
// with the abend details substituted into it.
void
Abnd_Exit(int signum)
{
  int          jmp_rc;
  _FEEDBACK    orig_tok;
  _FEEDBACK    fc;
  _CEECIB     *cib;
  char         module_name[181];
  char         lm_name[8];
  int          cond_offset;
  short        len;
  short        mod_name_len;
  short        i;
  char         lm_info[40];
  char         bb_str[120];
  char         abnd_msg[250];
  char         wto_msg[127];
  unsigned int abnd_code;

  jmp_rc = signum;
  printf("\nAbend has occurred.");
  cib = 0;
  CEEITOK(&orig_tok, &fc);
  CEE3CIB(&orig_tok, &cib, &fc);
  CEE3GRN(module_name, &fc);
  mod_name_len = strlen(module_name);
  for (i = mod_name_len; i>0; i--)
  {
    if (module_name[i] == ' ')
      module_name[i] = '\0';
  }
  CEE3GRO(&cond_offset, &fc);
  if (cib)
  {
    abnd_code = (cib->cib_abcd & 0x00fff000) / 4096;
    memcpy(lm_name, cib->cib_abname, 8);  // loadmod name from SDWA
    lm_info[0] = '\0';
    if (lm_name[0] != ' ' && lm_name[0] != '\0')
      sprintf(lm_info, " IN LOAD MODULE %s ", lm_name);
    if (lm_info[0] == '\0')
    {
      Find_LM(lm_info, (unsigned int)cib->cib_int);
    }

    if (cib->cib_bbranch == 1)
    {
      sprintf(bb_str, "BAD BRANCH DETECTED, BB_OFFSET= %X, BB_STATEMENT= %s ",
        cib->cib_bbranch_Offset, cib->cib_bbranch_StmtId);
    }
    else
      bb_str[0] = '\0';
    sprintf(abnd_msg, "XFRRSRVR: ABEND %3.3X HAS OCCURRED AT ADDRESS %-8.8X, "\
      "REASON CODE %8.8X, PROGRAM %s, OFFSET %8.8X%s %s",
      abnd_code, cib->cib_int, cib->cib_abrc, module_name, cond_offset, lm_info,
    printf("\nMsg prepared for reporting: \n%s", abnd_msg);
    if (comgcb && comgcb->comdvs)
    {
      len = strlen(abnd_msg);
      if (len > CHAR_DV_LGTH)
        len = CHAR_DV_LGTH;
      memcpy(comgcb->comdvs->rdtch1, abnd_msg, len);
    }
  }
  printf(" \n");
  printf(" \n");
  memcpy(wto_msg, "CXFAXFR003S ABEND DETECTED", 26);                 //D0017216-
  WTO(wto_msg);                                                      //D0017216-
  longjmp(jmp_ctl, jmp_rc);
}

//D0017425 following was put here to attempt proper abend reporting.
//  A serious shortcoming was discovered: when the abend happens in
//  a load module other than "this" load module then a second abend
//  will happen due to the way that IBMC corrupts addressability to
//  the global area (WSA)(and the global area is mandatory).
// This is now DEAD CODE.
void Abend_Reporter(_FEEDBACK *fc, _INT4 *token,
                    _INT4 *result, _FEEDBACK *newfc)         //D0017425
{
  _CEECIB       *cib;
  _FEEDBACK      cibfc;
  char         module_name[181];
  char         lm_name[8];
  char         lm_info[40];
  int          cond_offset;
  short        mod_name_len;
  short        i;
  short        len;
  unsigned int abnd_code;
  char         bb_str[120];
  char         abnd_msg[250];

  printf("\nAbend has occurred.");
  CEE3CIB(fc, &cib, &cibfc);
  if (_FBCHECK(cibfc, CEE000) != 0)
  {
    printf("CEE3CIB failed, CEE msg number is %d", cibfc.tok_msgno);
    exit(32);
  }

  memset(module_name, '\0', sizeof(module_name));
  CEE3GRN(module_name, fc);
  mod_name_len = strlen(module_name);
  for (i = mod_name_len; i>0; i--)
  {
    if (module_name[i] == ' ')
      module_name[i] = '\0';
  }
  CEE3GRO(&cond_offset, fc);
  if (cib)
  {
    abnd_code = (cib->cib_abcd & 0x00fff000) / 4096;
    memcpy(lm_name, cib->cib_abname, 8);  // loadmod name from SDWA
    lm_info[0] = '\0';
    if (lm_name[0] != ' ' && lm_name[0] != '\0')
      sprintf(lm_info, " in load module %s ", lm_name);
    if (lm_info[0] == '\0')
      Find_LM(lm_info, (unsigned int)cib->cib_int);
    // Write out a message to the trace file should be done here.
    if (cib->cib_bbranch == 1)
    {
      sprintf(bb_str, "Bad Branch Detected, bb_offset= %X, bb_statement= %s, %s
        cib->cib_bbranch_Offset, cib->cib_bbranch_StmtId);
    }
    else
      bb_str[0] = '\0';
    sprintf(abnd_msg, "Abend %3.3X has occurred at address %-8.8X, reason code %
      "program %s, offset %8.8X %s %s",
      abnd_code, cib->cib_int, cib->cib_abrc, module_name, cond_offset, lm_info,
    printf("\nMsg prepared for reporting: \n%s", abnd_msg);
    if (comgcb && comgcb->comdvs)
    {
      len = strlen(abnd_msg);
      if (len > CHAR_DV_LGTH)
        len = CHAR_DV_LGTH;
      memcpy(comgcb->comdvs->rdtch1, abnd_msg, len);
    }
  }

  proc_status = 'A';
#ifdef Dbg_Mode
  printf("\n Return to mainline");
  printf(" \n");
#endif
  *result = 10;   // This causes resulting action  (10 says resume, 20 percolate
  CEEMRCE(&abend_tok, fc);
#ifdef Dbg_Mode
  printf("\n After CEEMRCE");
  printf("\n");
#endif
}

// The purpose of this routine is to find the load module (and offset) that an a
//   - The address of the failure does not seem to be always sensible, good chan
//     library routine was executing and real error is in caller.  Could use R14
//     get closer to the cause.
//   - Also, if a bad branch is at fault (branch to 0) then R14 may also point t
static void
Find_LM(char *lm_info, unsigned int abend)
{
  struct xtlst                // eXTent LiST
  {
    int     xtllnth;          // length of extent list
    int     xtlnrfac;         // number of extents
    struct Xtlst_Ent
    {
      int     xtlmsbln;       // length of the load module
      int     xtlmsbad;       // Address of the load module
    }       xtlst_ent[1];
  };
  struct lle                  // Load List Element
  {
     struct lle *next;
     struct cde *llecdpt;
     short  rcount;
     short  scount;
  };
  struct cde                  // Contents Directory Entry (load module location)
  {
     struct cde *next;
     char   fill1[4];
     char   name[8];
     char   fill2[4];
     struct xtlst *cdxlmjp;
     short  cduse;
     char   lpdeattb;         // for CDE bit   .... 1... must be 0
                              // for LPDE bits 1... 1... must be 0... 1...
     char   fill3[5];
     int    lpdextln;         // length of storage block (if LPDE)
     unsigned int lpdextad;   // addr of main storage (if LPDE)
  };
  struct rb
  {
     void        *rbppsav;    // addr of problem prog reg. save area
     char         rbabopsw[4];// 4 low order bytes of name of req. routine
     short        rbsize;     // size of the RB in doublewords.
     char         rbstab1;    // bit switches: if 0x00 then we have PRB (problem
     char         rbstab2;    // bit switches:
     struct cde  *rbcde;      // addr of CDE for this rb.
     char         rbopsw[8];  // old psw
     char         filler[8];
     char         rbgrsave[64]; // gp reg save area
     char         fill2[208];
  };
  struct tcb
  {
     struct rb   *rbP;
     char         fill1a[8];
     struct tiot *tcbtio;
     char         fill1b[20];
     struct lle  *tcblls;
     struct dcb  *tcbjlb;
     char         fill2[72];
     struct tcb  *tcbtcb;
     char         fill3[4];
     struct tcb  *jobstepTcb;
     char         fill4[128];
     char         Id[3];
  };

  struct rb       *rbP;
  struct tcb      *tcbP;
  struct tcb     **anch;
  struct cde      *cdeP;
  struct lle      *lleP;
  struct xtlst    *xtlstP;
  long   int       wrk;
  char             lm_name[9];
  char             lm_info_str[40];
  unsigned int     addr;
  char             fnd_lm=0;
  unsigned int     lm_len;
  unsigned int     lm_addr;
           int     xl_num;
           int     off_set;
           int     cum_offset;

#ifdef Dbg_Mode
  printf("\nEnter Find_LM");
#endif
  addr = abend & 0x7fffffff;
#ifdef Dbg_Mode
  printf("\n addr looking for is %X", addr);
#endif
  anch = (void *) 0x21c;
  tcbP = *anch;                         /* start at current tcb  */
#ifdef Dbg_Mode
  printf("\ncur TCB@ =%X", tcbP);
#endif
  // The current TCB should be sufficient to get to the cause of the problem.
  rbP = tcbP->rbP;   // This gets us to the "rb" (Program Request Block)
  if (rbP->rbstab1 == 0x00)
  { // We have a PRB
    cdeP = rbP->rbcde;
#ifdef Dbg_Mode
    printf("\nCDE@ =%X, name=%8.8s", cdeP, cdeP->name);
#endif
    memcpy(lm_name, &cdeP->name[0], 8);
    lm_name[8] = '\0';  // nul term
    xtlstP = cdeP->cdxlmjp;
    cum_offset = 0;
    if (xtlstP)
    {
      for (xl_num=xtlstP->xtlnrfac; xl_num > 0; xl_num--)
      {
        // we are working from the end of the xtlst to the top
        lm_addr = xtlstP->xtlst_ent[xl_num-1].xtlmsbad & 0x7fffffff;
        lm_len = (xtlstP->xtlst_ent[xl_num-1].xtlmsbln) & 0x00ffffff;
        if (addr >= lm_addr)
        {
          off_set = addr - lm_addr;
          if (off_set <= lm_len)
          {
            off_set += cum_offset;
            sprintf(lm_info_str, ", IN LOAD MODULE %s, OFFSET %X", lm_name, off_
            // format lm_name and offset
            memcpy(lm_info, lm_info_str, 40);
            return;
          }
        }
        cum_offset += lm_len;
        xtlstP = ((void *)xtlstP) + 8;
      }
    }
    if ((cdeP->lpdeattb & 0x08) == 0x08)  // is it an lpde (vs. cde)?
    { // it is an LPDE
      if ((cdeP->lpdeattb & 0x04) == 0x00) // is it an extent list?
      {
        lm_addr = cdeP->lpdextad & 0x7fffffff;
        lm_len = cdeP->lpdextln;
        if (addr >= lm_addr)
        {
          off_set = addr - lm_addr;
          if (off_set <= lm_len)
          { // We found the load module that contains the address
            sprintf(lm_info_str, ", IN LOAD MODULE %s, OFFSET %X", lm_name, off_
            // format lm_name and offset
            memcpy(lm_info, lm_info_str, 40);
            // NOT so fast: if lm_name does not start with XFR or RDX or REL or
            //   back to a load module that DOES belong to us (use R14 in save a
            //   a C/CEE runtime routine.
            return;
          }
        }
      }
    }
  } // We have a PRB

//for(tcbP = tcbP->jobstepTcb; tcbP != NULL; tcbP = tcbP->tcbtcb)
//{
    if (memcmp(&tcbP->Id, "TCB", 3) == 0)
    {
      for (lleP = tcbP->tcblls; lleP != NULL;
           lleP = lleP->next)
      {
        wrk = (long int) lleP->llecdpt & 0x00ffffffL;
        if (wrk != NULL)              /*    100597 */
        {
          cdeP = lleP->llecdpt;
          memcpy(lm_name, &cdeP->name[0], 8);
          lm_name[8] = '\0';  // nul term
          xtlstP = cdeP->cdxlmjp;
          cum_offset = 0;
          if (xtlstP)
          {
            for (xl_num=xtlstP->xtlnrfac; xl_num > 0; xl_num--)
            {
              // we are working from the end of the xtlst to the top
              lm_addr = xtlstP->xtlst_ent[xl_num-1].xtlmsbad & 0x7fffffff;
              lm_len = (xtlstP->xtlst_ent[xl_num-1].xtlmsbln) & 0x00ffffff;
              if (addr >= lm_addr)
              {
                off_set = addr - lm_addr;
                if (off_set <= lm_len)
                {
                  off_set += cum_offset;
                  sprintf(lm_info_str, ", IN LOAD MODULE %s, OFFSET %X", lm_name
                  // format lm_name and offset
                  memcpy(lm_info, lm_info_str, 40);
                  return;
                }
              }
              cum_offset += lm_len;
              xtlstP = ((void *)xtlstP) + 8;
            }
          }
          if ((cdeP->lpdeattb & 0x08) == 0x08)  // is it an lpde (vs. cde)?
          { // it is an LPDE
            if ((cdeP->lpdeattb & 0x04) == 0x00) // is it an extent list?
            {
              lm_addr = cdeP->lpdextad & 0x7fffffff;
              lm_len = cdeP->lpdextln;
              if (addr >= lm_addr)
              {
                off_set = addr - lm_addr;
                if (off_set <= lm_len)
                { // We found the load module that contains the address
                  sprintf(lm_info_str, ", IN LOAD MODULE %s, OFFSET %X", lm_name
                  // format lm_name and offset
                  memcpy(lm_info, lm_info_str, 40);
                  // NOT so fast: if lm_name does not start with XFR or RDX or R
                  //   back to a load module that DOES belong to us (use R14 in
                  //   a C/CEE runtime routine.
                  return;
                }
              }
            }
          }
        }
      }
    }
//}
  return;
}

static void
//Trace_Inp(FILE *trc_file, struct FXSERV_Parms *fx_parms)
// ... uhhh ... trc_file isn't used anywhere ...
Trace_Inp (struct FXSERV_Parms *fx_parms,
           FILE                 *xfrtrc)                     //cwe134588
{
  short offset;
  char  prt_line[132], wrk_area[9];
  int  *d_ptr;
  char *d1_ptr;
  char *pl_ptr;
  char  w_char;
  short i,j;
  struct Val_Area                   // (taken from fxxplist macro)        misc1
  {
    int                 list_len;   // size of storage getmained
    char               *cur_pos;    // address of current entry (end of list)
    int                 entry_cnt;  // number of entries
    int                 entry_size; // size of each list element
    short               fill1;
    short               subpool;
    int                 reserved;
    char                data[1];    // Beginning of first list entry
  }                    *list_values;

  d_ptr = (int *)&fx_parms->xmlplist->u.fr;
  d1_ptr = (char *)&fx_parms->xmlplist->u.fr;
  fprintf (xfrtrc, "\n             First 96 bytes of input:");   //cwe134588

  for (offset = 0; offset < 96; offset += 32)
  {
    memset(prt_line, ' ', 132);
    sprintf(wrk_area, "%4.4X", offset);
    memcpy(prt_line, wrk_area, 4);
    pl_ptr = prt_line;
    pl_ptr += 5;

    for (i=1; i<=2; i++)
    {
      pl_ptr += 3;
      for (j=0; j<4; j++)
      {
        sprintf(wrk_area, "%8.8X", *d_ptr);
        memcpy(pl_ptr, wrk_area, 8);
        pl_ptr += 9;
        d_ptr++;
      }
    }

    pl_ptr += 2;
    *pl_ptr = '*';
    pl_ptr++;

    for (i=1; i<=32; i++)
    {
      w_char = *d1_ptr;
      if (w_char >= ' ')
        *pl_ptr = w_char;
      else
        *pl_ptr = '.';
      pl_ptr++;
      d1_ptr++;
    }
    *pl_ptr = '*';
    fprintf (xfrtrc, "\n%-132.132s", prt_line);      //cwe134588
    fflush (xfrtrc);
  }

  if (fx_parms->xmlplist->u.fr.frreq == 1001)
  {
    fprintf (xfrtrc, "\nFilter parameters:");                            //cwe13
    fprintf (xfrtrc, "\n  number creators=%d, number HLQs=%d", fx_parms->xmlplis
                     fx_parms->xmlplist->xml_hql_ct);
    i = fx_parms->xmlplist->xml_crtr_ct;
    list_values = (struct Val_Area *)fx_parms->xmlplist->xml_crtr;
    fprintf (xfrtrc, "\n  creator filter: buffer size = %8.8X, %d entries, entry
                      list_values->list_len, list_values->entry_cnt, list_values
    list_values = (struct Val_Area *)fx_parms->xmlplist->xml_hlq;
    fprintf (xfrtrc, "\n  HLQ filter: buffer size = %8.8X, %d entries, entry siz
                     list_values->list_len, list_values->entry_cnt, list_values-
    d1_ptr = fx_parms->xmlplist->xml_crtr;
    d1_ptr += 24; // first entry is 24 bytes in.

    for (;i>0;i--)
    {
      memset (prt_line, ' ', 132);
      memcpy (&prt_line[0], "CRT ", 4);
      memcpy (&prt_line[4], d1_ptr, 128);
      fprintf (xfrtrc, "\n%-132.132s", prt_line);                           //cw
      d1_ptr += 128;
      memset (prt_line, ' ', 4);
      memcpy (&prt_line[4], d1_ptr, 128);
      fprintf (xfrtrc, "\n%-132.132s", prt_line);                           //cw
      d1_ptr += 128;
    }

    i = fx_parms->xmlplist->xml_hql_ct;
    d1_ptr = fx_parms->xmlplist->xml_hlq;
    d1_ptr += 24; // first entry is 24 bytes in.

    for (;i>0;i--)
    {
      memset (prt_line, ' ', 132);
      memcpy (&prt_line[0], "HLQ ", 4);
      memcpy (&prt_line[4], d1_ptr, 17);
      fprintf (xfrtrc, "\n%-21.21s", prt_line);                             //cw
      d1_ptr += 17;
    }
    fprintf (xfrtrc, "\n ");                                                //cw
  }

  fflush (xfrtrc);                                                          //cw

  return;
}

// D0017439 Following was re-located/refactored from XFRRAF
//static void                                                 CWE147671
static short                                                //CWE147671
Initialize_Environ(struct comgcb **comgcb_ptr, struct PrmRAF *prmraf)
{
  struct prmrdxgsu       prmrdxgsu;
  struct prmrddrv        prmrddrv;
  struct Gbl_Vis_Data   *gbl_vis_data;
  struct comgcb         *comgcb;
  short                  dd_fnd;                             //D0016288
  //Text units and request block needed for dynamic          //D0016288
  //allocation of SYSOUT   to SYSOUT=* (if not coded in JCL) //D0016288
  struct textunit                                            //D0016288
    {                                                        //D0016288
    short  key;                                              //D0016288
    short  quantity;                                         //D0016288
    short  lgth;                                             //D0016288
    union  data                                              //D0016288
      {                                                      //D0016288
      char  ddname[8];                                       //D0016288
      char  sysout;                                          //D0016288
      } data;                                                //D0016288
    };                                                       //D0016288
                                                             //D0016288
  struct reqblk                                              //D0016288
    {                                                        //D0016288
    short   lgth_and_verb;                                   //D0016288
    short   flags;                                           //D0016288
    short   error_code;                                      //D0016288
    short   info_code;                                       //D0016288
    void    *text_ptr;                                       //D0016288
    char    *reserved;                                       //D0016288
    char    *flags2;                                         //D0016288
    };                                                       //D0016288
                                                             //D0016288
  struct reqblk   reqblk;                                    //D0016288
  struct textunit tu_ddname;                                 //D0016288
  struct textunit tu_sysout;                                 //D0016288
  struct textunit *tu_ptrs[2];                               //D0016288
  struct reqblk   *reqblk_ptr;                               //D0016288
  unsigned long   svc_code;                                  //D0016288
  struct Err_Dtl *err_dtl;                                   //D0017439

  memset(&prmrdxgsu, '\0', sizeof(struct prmrdxgsu));
  prmrdxgsu.request = RDXGSU_REL_OPT_START;
  prmrdxgsu.calling_appl = 'R';
  memset(&prmrddrv, '\0', sizeof(struct prmrddrv));
  prmrdxgsu.rdprm = &prmrddrv;
  prmrddrv.option = 'V';       // Signal that this is Visualizer   D0016288
  prmrddrv.operating_mode = 'B';
  prmrddrv.test_mode_ind  = ' ';
  memcpy(prmrddrv.msg_prefix, "RDX", 3);

  // D0016288 - allocate SYSOUT here.
  dd_fnd = osddinfo("sysout", NULL, NULL, NULL, NULL, NULL);     //D0016288

  if (dd_fnd != 0)                                               //D0016288
  {
    // sysout not found, so allocate one                         //D0016288
    reqblk_ptr = (struct reqblk *) (((long) &reqblk) ¦ 0x80000000); //D0016288
    reqblk.lgth_and_verb = 0x1401;                         //D0016288
    reqblk.flags         = 4096;   //Found in XFABBASE       D0016288
    reqblk.error_code    = 0;                              //D0016288
    reqblk.info_code     = 0;                              //D0016288
    reqblk.text_ptr      = (void *) tu_ptrs;               //D0016288
    reqblk.reserved      = NULL;                           //D0016288
    reqblk.flags2        = NULL;                           //D0016288
    tu_ddname.key        = 0x0001; //DDNAME key              D0016288
    tu_ddname.quantity   = 1;                              //D0016288
    tu_ddname.lgth       = 8;                              //D0016288

    // It would be really nice to set RECFM,LRECL,BLKSIZE
    memcpy (tu_ddname.data.ddname, "SYSOUT  ", 8);         //D0016288
    tu_sysout.key        = 0x0018; //SYSOUT class key        D0016288
    tu_sysout.quantity   = 0;      //Found this            //D0016288
    tu_sysout.lgth       = 0;      // online               //D0016288
    tu_sysout.data.sysout  = NULL; //Use null not asterisk   D0016288
    tu_ptrs[0] = &tu_ddname;                               //D0016288
    tu_ptrs[1] = &tu_sysout;                               //D0016288
    tu_ptrs[1] =                                           //D0016288
      (struct textunit *) (((long) tu_ptrs[1]) ¦ 0x80000000); //D0016288

    svc_code = svc99( (__S99parms *)&reqblk);              //D0016288

    if (svc_code)                                          //D0016288
    {                                                    //D0016288
      printf("\nError allocating SYSOUT. ");               //D0016288
    }                                                    //D0016288
  }                                                              //D0016288

  RDXGSU(&prmrdxgsu);

  // D0016288 - test here for what is truly a fatal error.
  comgcb = prmrdxgsu.comgcb;
  if (prmrdxgsu.err_code != 0)
  {
    err_dtl = prmraf->err_dtl;
    if (err_dtl == 0)
    {
      err_dtl = (struct Err_Dtl *)malloc(sizeof(struct Err_Dtl));
      memset(err_dtl, '\0', sizeof(struct Err_Dtl));
      prmraf->err_dtl = err_dtl;
    }
    err_dtl->err_code = prmrdxgsu.err_code;
    prmraf->err_dtl = err_dtl;
    prmraf->rc = 16;
    memset(err_dtl->msg_id, ' ', 8);
    memset(err_dtl->msg_text, ' ', sizeof(err_dtl->msg_text));
    printf("\nRDXGSU returned error code %d.", prmrdxgsu.err_code);
//  return;                                                   CWE147671
    return(prmrdxgsu.err_code);                             //CWE147671
  }
  comgcb = prmrdxgsu.comgcb;                                      //D0016169
  comgcb->privacy_project_name = malloc(PRIVACY_PROJ_NAME_LEN);   //D0016169
  comgcb->privacy_project_uuid = malloc(PRIVACY_PROJ_UUID_LEN);   //D0016169
  comgcb->privacy_repository_name = malloc(PRIVACY_PROJ_NAME_LEN);//D0016169
  gbl_vis_data = prmraf->gbvisraf;
  gbl_vis_data->comgcb = comgcb;                                  //D0016169
  *comgcb_ptr = comgcb;
  return(0);                                                //CWE147671
}

// --------------------------------------------------------------------------- /
// CWE101609 - Routine written to support multi-byte input from Topaz.         /
// --------------------------------------------------------------------------- /
static short
Get_Multi_Block_Data (struct multi_block_data *mb_data,
                      struct FXSERV_Parms *fx_parms,
                      short diag_ind,
                      struct PrmRAF *prmraf,
                      void **reg1,
                      FILE *xfrtrc)              //cwe134588
{
  short offset;
  char  prt_line[132];
  char  wrk_area[9];
  int  *d_ptr;
  char *d1_ptr;
  char *pl_ptr;
  char  w_char;
  short i,j;

  char             *buff_addr;
  struct xmlplist  *xmlplist;
  struct prmsdrcv  *sd_rcv_prm;
  ioBlock_t        *xml_ctl;
  unsigned int      space_needed;
  unsigned int      mem_size;
  unsigned int      fx_buffer_len;
  enum serviceCodes op_post=POST_ECB;
  enum serviceCodes op_wait_1=WAIT_ONE_ECB;
  int               recv_func=8;
  char              xfr_flag;            // addr of FRFLAG (major signal flag)
  short             rc=0;
  char              wto_msg[127];                        //D0017216-2

  if (diag_ind)
    fprintf (xfrtrc, "\n%s:%s:Entry\n", __FILE__, __FUNCTION__);

  xmlplist = fx_parms->xmlplist;
  //space_needed = xmlplist->mbnbyte * xmlplist->mbntran;      //CWE149503
  space_needed = xmlplist->mbnbyte;                          //CWE149503
  if (space_needed > mb_data->buff_size)
  {
    free(mb_data->buffer);
    mem_size = space_needed / 4096;
    mem_size = (mem_size + 1) * 4096;
    buff_addr = malloc(mem_size);
    if (buff_addr == NULL)
    {
#define MALLOC_FAIL -2506 // RDXE506
      rc = MALLOC_FAIL;
      return rc;
    }
    mb_data->buffer = buff_addr;
    mb_data->buff_size = mem_size;
    mb_data->used_size = 0;
  }

  if (diag_ind)
    fprintf (xfrtrc, "\nXFRRSRVR receiving multi-block input.");          //cwe1

  *fx_parms->ecb_sdrcv = 0;
  sd_rcv_prm = fx_parms->prm_sdrcv;
  sd_rcv_prm->srtrnsmt = xmlplist->mbntran;
  sd_rcv_prm->srlen = xmlplist->mbnbyte;
  sd_rcv_prm->srdata = mb_data->buffer;
  sd_rcv_prm->srxib = fx_parms->tpx_in_buf;
  sd_rcv_prm->srlast = 'N';
  sd_rcv_prm->srtrnslt = 'N';

  // This is requesting a receive operation
  CWASMSRV(&op_post, *reg1, fx_parms->ecb_func_compl, &recv_func);
  CWASMSRV(&op_wait_1, *reg1, fx_parms->ecb_sdrcv);
  fx_buffer_len = *fx_parms->tpx_bufln;
  xfr_flag = *fx_parms->xfr_flag;
  mb_data->used_size = xmlplist->mbnbyte;

  if (diag_ind)
  {
    fprintf (xfrtrc, "\n%s: mbnbyte : %d; mbntran : %d; mbtrans %c\n",
                     __FUNCTION__,
                     xmlplist->mbnbyte,
                     xmlplist->mbntran,
                     xmlplist->mbtrans);         //cwe134588
    if (xmlplist->mbnbyte > 0)
    {
      // dump the first 96 bytes of multiblock data
      //d_ptr = (int *)&fx_parms->xmlplist->u.fr;
      //d1_ptr = (char *)&fx_parms->xmlplist->u.fr;
      d_ptr = (int *) mb_data->buffer;
      d1_ptr = (char *) mb_data->buffer;
      fprintf (xfrtrc, "\n             First 96 bytes of multiblock data:");   /

      for (offset = 0; offset < 96; offset += 32)
      {
        memset (prt_line, ' ', 132);
        sprintf (wrk_area, "%4.4X", offset);
        memcpy (prt_line, wrk_area, 4);
        pl_ptr = prt_line;
        pl_ptr += 5;

        for (i=1; i<=2; i++)
        {
          pl_ptr += 3;
          for (j = 0; j < 4; j++, d_ptr++, pl_ptr += 9)
          {
            sprintf (wrk_area, "%8.8X", *d_ptr);
            memcpy (pl_ptr, wrk_area, 8);
          }
        }

        pl_ptr += 2;
        *pl_ptr = '*';
        pl_ptr++;

        for (i = 1; i <= 32; i++, pl_ptr++, d1_ptr++)
        {
          w_char = *d1_ptr;
          if (w_char >= ' ')
            *pl_ptr = w_char;
          else
            *pl_ptr = '.';
        }

        *pl_ptr = '*';
        fprintf (xfrtrc, "\n%-132.132s", prt_line);      //cwe134588
        fflush (xfrtrc);
      }
    }
  }

  if (xfr_flag & FORCEEND+SHUTDOWN)
  {
    if (xfr_flag & SHUTDOWN)
    {
      if (diag_ind)
         fprintf (xfrtrc, "\nReceived HCI shutdown notification.");         //cw

      // Set variables in msg_dtl for explanation
      //   Probably do NOT want to send such a message - WB should already be go
      //   if this is a normal shutdown.
      //                                                                       D
      memcpy(wto_msg, "CXFAXFR004W HCI SHUTDOWN NOTIFICATION RECEIVED.", 47);//D
      WTO(wto_msg);                                                          //D
      //prmraf->err_dtl->err_code = -7409;// HCI shutdown notification         D
      prmraf->err_dtl->err_code = RDXEE409;                       //CWE107575

      XFRXENCD(prmraf);    // Encode the output into XML

      xml_ctl = prmraf->vis_raf_out->xml_ctl;
      sd_rcv_prm->srdata = xml_ctl->ioBuffer;
      sd_rcv_prm->srlen = xml_ctl->bufferSize - xml_ctl->bytesRemaining;
      rc = 16;
    }
    else
    {
      if (diag_ind)
        fprintf (xfrtrc, "\nForced Ending by FXSERVER. Check FDBK code.");     /

      memcpy(wto_msg, "CXFAXFR003S FORCED END BY FXSERVER.", 35);           //D0
      WTO(wto_msg);                                                         //D0
      //prmraf->err_dtl->err_code = -7410;// HCI forced shutdown               D
      prmraf->err_dtl->err_code = RDXEE410;                       //CWE107575

      XFRXENCD(prmraf);    // Encode the output into XML

      xml_ctl = prmraf->vis_raf_out->xml_ctl;
      sd_rcv_prm->srdata = xml_ctl->ioBuffer;
      sd_rcv_prm->srlen = xml_ctl->bufferSize - xml_ctl->bytesRemaining;
      rc = 16;
    }
  }

  if (diag_ind)                          //cwe134588
    fflush (xfrtrc);                     //cwe134588

  return rc;
}

// ==================================================================
//
// get the error message associated with an RDX error number
//
//
// ==================================================================

static short
Geterrmsg (struct PrmRAF   *prmraf)
{
  struct Err_Dtl     *err_dtl = NULL;
  struct comgcb      *comgcb = NULL;                        //D0016408
  struct xvjopunv    *xvjopunv = NULL;                      //D0016408
  struct prmcvmsg     prmcvmsg;                             //D0016408
  struct prmgtmsg     prmgtmsg;

  struct comioc      *comioc;                               //D0016408
  struct comemc      *comemc;                               //D0016408
  struct Gbl_Vis_Data *gbvisraf;                            //D0017366

  static short        mlib_alloc=-1;                        //D0016408
  int                 rc=-1;                                //D0016408
  int                 text_len;                             //D0016408
  int                 text_p1_len;                          //CWE83998
  int                 text_p2_len;                          //CWE83998
  int                 msg_max_len;                          //CWE83998
  char               *text_ptr;                             //CWE83998

  void              (*cvmsg_FP)();                          //D0016408
  void              (*gtmsg_FP)();                          //D0016408
  short               ix;                                   //D0016408
  short               hex_len;                              //CWE83998A
  char                alloc_txt[90];                        //D0016408
  char                err_txt[80];                          //D0016408
  char                wrk_str[80];                          //D0016408
  char                mlib_misg_text[90];                   //D0016408
  void              (*frt_FP)();                            //D0016408
  struct prmfrt       prmfrt;                               //D0016408
  char                japanese_support = 0;                     //D0017366

  comgcb = prmraf->gbvisraf->comgcb;                        //D0016408
  err_dtl = prmraf->err_dtl;                                //D0016408
  mlib_alloc = osddinfo ("rdxmlib", NULL, NULL, NULL, NULL, NULL);//CWE103802

  cvmsg_FP = comgcb->comciovt->addr_CVMSG;                //D0016408
  gtmsg_FP = comgcb->comciovt->addr_GTMSG;                //D0016408
  frt_FP   = (void (*)())comgcb->comciovt->addr_FRT;          //D0016408

  if (mlib_alloc != 0)                                      //CWE103802
  {                                                         //D0016408
    if (comgcb)                                             //D0016408
      xvjopunv = comgcb->xvjopunv;                          //D0016408

    if (xvjopunv)                                           //D0016408
    {                                                       //D0016408
      if (xvjopunv->DBCS_support == 'Y')                    //D0017366
        japanese_support = 1;                               //D0017366
      memcpy (wrk_str, xvjopunv->smpe_msg_lib, 44);          //D0016408

      if (japanese_support)                                 //D0017366
        memcpy (wrk_str, xvjopunv->smpe_jpn_msg_lib, 44);    //D0017366

      for (ix = 43; ix > 0; ix--)                               //D0016408
      {                                                     //D0016408
        if (wrk_str[ix] != ' ')                             //D0016408
          break;                                            //D0016408
      }                                                     //D0016408
      wrk_str [ix+1] = 0;                                   //D0016408
      memset (alloc_txt, 0, sizeof (alloc_txt));            //D0016408
      sprintf (alloc_txt, "ddn=rdxmlib,dsn=\'%s\',disp=shr", wrk_str);
      rc = osdynalloc (DYN_ALLOC, alloc_txt, err_txt);       //D0016408
    }                                                       //D0016408
                                                            //D0016408
    if (rc == 0)                                            //D0016408
      mlib_alloc = 0;                                       //D0016408
    else                                                    //D0016408
    {                                                       //D0016408
      //printf("\nError allocating RDXMLIB ");                //D0016408
      return (-1);                                          //D0016408
    }                                                       //D0016408
  }                                                         //D0016408

  if (mlib_alloc == 0)                                      //CWE103802
  {                                                         //D0016408
    // retrieve the message text by call to GTMSG.          //D0016408
    comioc = comgcb->comioc;                                //D0016408
    comemc = comioc->comemc;                                //D0016408
    comemc->flag_mlib_fcb_unavail = 'N';                    //D0016408
    // The above is because RDXGSU did not have RDXMLIB alloc prior to exec.
    // The message code (RDX message code, not ISPF MSGID) will be in err_dtl->e

    memset (&prmcvmsg, ' ', sizeof (prmcvmsg));               //D0016408
    prmcvmsg.error_code = err_dtl->err_code;                //D0016408
    prmcvmsg.comemc = comemc;                               //D0016408
    prmcvmsg.msg_id = err_dtl->msg_id;                      //D0016408
    cvmsg_FP (&prmcvmsg);                                    //D0016408
                                                            //D0016408
    memset (&prmgtmsg, ' ', sizeof (prmgtmsg));               //D0016408
    prmgtmsg.error_code = err_dtl->err_code;                //D0016408
                                                            //D0016408B
    prmgtmsg.product_dvdefns = comgcb->gtmsg_dvdefn;        //D0016408
    prmgtmsg.comioc = comgcb->comioc;                       //D0016408
    gtmsg_FP (&prmgtmsg);                                    //D0016408

    text_p1_len = prmgtmsg.long_text_lgth;                  //CWE83998
    text_p2_len = strlen (prmgtmsg.extended_help_text);      //CWE83998
    msg_max_len = sizeof (err_dtl->msg_text);                //CWE83998
    memset (err_dtl->msg_text, ' ', msg_max_len);            //CWE83998
    memcpy (err_dtl->msg_text, prmgtmsg.long_text, text_p1_len);//CWE83998
    text_ptr    = err_dtl->msg_text + text_p1_len + 1;         //CWE83998
    text_len    = text_p1_len + text_p2_len + 1;               //CWE83998

    if (text_len > msg_max_len)                             //CWE83998
    {                                                       //CWE83998
      text_len = msg_max_len;                               //CWE83998
      text_p2_len = msg_max_len - text_p1_len - 1;          //CWE83998
    }                                                       //CWE83998

    if (text_p2_len > 0)                                    //CWE83998
      memcpy (text_ptr, prmgtmsg.extended_help_text,        //CWE83998
              text_p2_len);                                       //CWE83998

    // Prior to freeing the RDXMLIB, first must close the
    // file (it is opened by GTMSG and left open).
    if (comemc->mlib_fcb != 0)
    {
      prmfrt.fcb = comemc->mlib_fcb;
      prmfrt.flag_update_dir_stats = 'N';
      prmfrt.ispf_dir_suffix_lgth = 0;
      memset (prmfrt.ispf_dir_suffix, ' ', 30);
      prmfrt.override_disp_to_del = 'N';
      frt_FP (&prmfrt);
      comemc->mlib_fcb = 0;
    }
    rc = osdynalloc (DYN_FREE, "ddn=rdxmlib,disp=keep",     //D0016408
                     err_txt);                                           //D0016
    if (rc == 0)                                            //D0016408
      mlib_alloc = -1;                                      //D0016408
                                                            //D0016408
  }                                                         //D0016408
  else                                                      //D0016408
  {
    // RDXMLIB not allocated. return failure
    return (-1);
  }

  return 0;
}
//
// hex2chr ()
//
// receives ebcdic hex string, converts them
// to displayable characters
//
static void  hex2chr (int   length,        // length of output char area
                      char *hex_in,
                      char *char_out)
{
  char     *in_ptr;
  char     *out_ptr;
  short     wrk;
  short     wrk_out;
  short     low_nyb;
  short     high_nyb;
  short     nybble;
  short     cur_ent;
  short     indx;
  short     hi_lo;

  in_ptr = hex_in;
  out_ptr = char_out;
  memset (out_ptr, ' ', length);

  //
  // stopgap effort: just move the hex_in to char out till
  // the stuff actually comes to us in hex
  //
  // ok, as of 3:17, Oct 24, they're ready for the hex jcl
  //memcpy (char_out, hex_in, length);
  //return;

  hi_lo = 1;
  //for (indx = 0; indx < length; indx++)
  //
  // The length is coming in as the output length/
  // the length of the character job card.
  // The length of the string to convert is twice as long.
  //
  for (indx = 0; indx < length * 2; indx++)
  {
    if (*in_ptr == ' ')
      break;
    wrk = *in_ptr;
    if (wrk > 239)
      nybble = wrk - 240;   // 0 through 9
    else
      nybble = (wrk - 193) + 10; // 10 through 15

    if (hi_lo == 1)
      high_nyb = nybble;
    else
    {
      low_nyb = nybble;
      *out_ptr = high_nyb*16 + low_nyb;
      out_ptr++;
    }
    hi_lo = 1 - hi_lo;
    in_ptr++;
  }

 return;
}

// debug function: dump the execreq data received
//
// add multiblock pointer; dump input request (load)
static void         prreqinfo (struct xmlplist         *xmlplist,
                               struct multi_block_data *mb_data)    //cwe146334
{
  char       temp80[80];
  struct tm *wktime;                                   //cwe139432
  time_t     wksecs;                                   //cwe139432
  char       date_time[20];                            //cwe134588
  unsigned int offset;                                       //CWE149503

  char  prt_line[132];
  char  wrk_area[9];
  int  *d_ptr;
  char *d1_ptr;
  char *pl_ptr;
  char  w_char;
  short i,j;

  time (&wksecs);                                            //cwe134588
  wktime = localtime (&wksecs);                              //cwe134588
  strftime (date_time, 20,"%Y/%m/%d %H:%M:%S", wktime);      //cwe134588

  fprintf (xfrtrc, "\n%s XFRRSRVR: Received EXECREQ request\n", date_time);

  memset (temp80, 0x00, sizeof(temp80));
  memcpy (temp80, xmlplist->u.fr.fr_reqdsn, 56);
  fprintf (xfrtrc, "\n        FRREQDSN >>>%s<<<", temp80);
  memcpy (temp80, xmlplist->u.fr.fr_extdsn, 56);
  fprintf (xfrtrc, "\n        FREXTDSN >>>%s<<<", temp80);

  memset (temp80, 0x00, sizeof(temp80));
  memcpy (temp80, xmlplist->u.fr.fr_jclln1, 72);
  fprintf (xfrtrc, "\n        FRJCLLINE1 >>>%s<<<", temp80);
  memset (temp80, 0x00, sizeof(temp80));
  memcpy (temp80, xmlplist->u.fr.fr_jclln1 + 72, 72);
  fprintf (xfrtrc, "\n                   >>>%s<<<", temp80);

  memcpy (temp80, xmlplist->u.fr.fr_jclln2, 72);
  fprintf (xfrtrc, "\n        FRJCLLINE2 >>>%s<<<", temp80);
  memset (temp80, 0x00, sizeof(temp80));
  memcpy (temp80, xmlplist->u.fr.fr_jclln2 + 72, 72);
  fprintf (xfrtrc, "\n                   >>>%s<<<", temp80);

  memcpy (temp80, xmlplist->u.fr.fr_jclln3, 72);
  fprintf (xfrtrc, "\n        FRJCLLINE3 >>>%s<<<", temp80);
  memset (temp80, 0x00, sizeof(temp80));
  memcpy (temp80, xmlplist->u.fr.fr_jclln3 + 72, 72);
  fprintf (xfrtrc, "\n                   >>>%s<<<", temp80);

  memcpy (temp80, xmlplist->u.fr.fr_jclln4, 72);
  fprintf (xfrtrc, "\n        FRJCLLINE4 >>>%s<<<", temp80);
  memset (temp80, 0x00, sizeof(temp80));
  memcpy (temp80, xmlplist->u.fr.fr_jclln4 + 72, 72);
  fprintf (xfrtrc, "\n                   >>>%s<<<", temp80);

  memcpy (temp80, xmlplist->u.fr.fr_jclln5, 72);
  fprintf (xfrtrc, "\n        FRJCLLINE5 >>>%s<<<", temp80);
  memset (temp80, 0x00, sizeof(temp80));
  memcpy (temp80, xmlplist->u.fr.fr_jclln5 + 72, 72);
  fprintf (xfrtrc, "\n                   >>>%s<<<", temp80);

  memcpy (temp80, xmlplist->u.fr.fadebug, 56);
  fprintf (xfrtrc, "\n        FADEBUG    >>>%s<<<", temp80);
  memcpy (temp80, xmlplist->u.fr.fajpath, 56);
  fprintf (xfrtrc, "\n        FAJPATH    >>>%s<<<", temp80);
  memcpy (temp80, xmlplist->u.fr.fajopts, 56);
  fprintf (xfrtrc, "\n        FAJOPTS    >>>%s<<<", temp80);
  memcpy (temp80, xmlplist->u.fr.faipaddr, 56);
  fprintf (xfrtrc, "\n        FAIPADDR   >>>%s<<<", temp80);
  memcpy (temp80, xmlplist->u.fr.faexpath, 56);
  fprintf (xfrtrc, "\n        FAEXPATH   >>>%s<<<", temp80);
  memcpy (temp80, xmlplist->u.fr.frjclout, 56);              //CWE149678
  fprintf (xfrtrc, "\n        FRJCLOUT   >>>%s<<<", temp80); //CWE149678

  // start dumping the request file portion                    cwe146334
  // dump the first 96 bytes of multiblock data
  d_ptr = (int *) mb_data->buffer;
  d1_ptr = (char *) mb_data->buffer;
  // ok, complete multiblock is ... crazy
  //fprintf (xfrtrc, "\n      Complete multiblock data (length:%d)",
  //         mb_data->buff_size);

  //fprintf (xfrtrc, "\n      Complete multiblock data (length:%d)",
  //for (offset = 0; offset < mb_data->buff_size; offset += 32)
  fprintf (xfrtrc, "\n      First 1024 bytes of multiblock data");
  for (offset = 0; offset < 1024; offset += 32)
  {
    memset (prt_line, ' ', 132);
    sprintf (wrk_area, "%8.8X", offset);
    //memcpy (prt_line, wrk_area, 4);                          //CWE149503
    memcpy (prt_line, wrk_area, 8);                          //CWE149503
    pl_ptr = prt_line;
    //pl_ptr += 4;                                             //CWE149503
    pl_ptr += 8;                                             //CWE149503

    for (i=1; i<=2; i++)
    {
      pl_ptr += 3;
      for (j = 0; j < 4; j++, d_ptr++, pl_ptr += 9)
      {
        sprintf (wrk_area, "%8.8X", *d_ptr);
        memcpy (pl_ptr, wrk_area, 8);
      }
    }

    pl_ptr += 2;
    *pl_ptr = '*';
    pl_ptr++;

    for (i = 1; i <= 32; i++, pl_ptr++, d1_ptr++)
    {
      w_char = *d1_ptr;
      if (w_char >= ' ')
        *pl_ptr = w_char;
      else
        *pl_ptr = '.';
    }

    *pl_ptr = '*';
    fprintf (xfrtrc, "\n%-132.132s", prt_line);      //cwe134588
  }  // end of "for (offset = 0 ..."

  return;
}

//
// debug function: dump the ri_load data received
//
static void
prrildinfo (struct xmlplist *xmlplist)
{
  char       temp80[80];
  struct tm *wktime;                                   //cwe139432
  time_t     wksecs;                                   //cwe139432
  char       date_time[20];                            //cwe134588

  time (&wksecs);                                            //cwe134588
  wktime = localtime (&wksecs);                              //cwe134588
  strftime (date_time, 20,"%Y/%m/%d %H:%M:%S", wktime);      //cwe134588
  fprintf (xfrtrc, "\n%s XFRRSRVR: Received GETRIREL request\n", date_time);

  memset (temp80, 0, sizeof (temp80));
  memcpy (temp80, xmlplist->u.fr.fr_reldsn, 44);
  fprintf (xfrtrc, "\n        reldsn     >>>%s<<<", temp80);

  memset (temp80, 0, sizeof (temp80));
  memcpy (temp80, xmlplist->u.fr.fr_ssid, 8);
  fprintf (xfrtrc, "\n        fr_ssid    >>>%s<<<", temp80);

  memset (temp80, 0, sizeof (temp80));
  memcpy (temp80, xmlplist->u.fr.fr_loc, 16);
  fprintf (xfrtrc, "\n        fr_loc     >>>%s<<<", temp80);

  memset (temp80, 0, sizeof (temp80));
  memcpy (temp80, xmlplist->u.fr.fr_creator, 64);
  fprintf (xfrtrc, "\n        fr_creator >>>%s<<<", temp80);
  memcpy (temp80, xmlplist->u.fr.fr_creator + 64, 64);
  fprintf (xfrtrc, "\n                   >>>%s<<<", temp80);
  memcpy (temp80, xmlplist->u.fr.fr_creator + 128, 64);
  fprintf (xfrtrc, "\n                   >>>%s<<<", temp80);
  memcpy (temp80, xmlplist->u.fr.fr_creator + 192, 64);
  fprintf (xfrtrc, "\n                   >>>%s<<<", temp80);

  memset (temp80, 0, sizeof (temp80));
  memcpy (temp80, xmlplist->u.fr.fr_tbname, 44);
  fprintf (xfrtrc, "\n        fr_tbname  >>>%s<<<", temp80);
  memcpy (temp80, xmlplist->u.fr.fr_tbname + 64, 64);
  fprintf (xfrtrc, "\n                   >>>%s<<<", temp80);
  memcpy (temp80, xmlplist->u.fr.fr_tbname + 128, 64);
  fprintf (xfrtrc, "\n                   >>>%s<<<", temp80);
  memcpy (temp80, xmlplist->u.fr.fr_tbname + 192, 64);
  fprintf (xfrtrc, "\n                   >>>%s<<<", temp80);

  memset (temp80, 0, sizeof (temp80));
  memcpy (temp80, xmlplist->u.fr.fr_scope, 1);
  fprintf (xfrtrc, "\n        fr_scope   >>>%s<<<", temp80);

  fprintf (xfrtrc, "\n        fetch_cnt  >>>%d  <<<",
           xmlplist->u.fr.fr_fetch_cnt);

  return;
}


//
// build the object linked list, by parsing out
// the multi-block data. The multi-block data is a string
// of creators/table names or mvs layout/01 level names,
// each null terminated.
//
//static int bldcrtb (struct xmlplist         *xmlplist,      CWE152293
static int bldobjtab (struct xmlplist       *xmlplist,      //CWE152293
                    struct multi_block_data *mb_data,
                    struct prmtbmet         *prmtbmet,      //CWE152293
                    char          *db2_flag_1008_1009)      //CWE152293
{
  char  *dptr;      // running pointer to location in the multiblock

  char   cre [CRTR_NAME_LGTH + 1];
  char   tab [TBL_NAME_LGTH + 1];
  int    tabcnt = 0;
  int    i = 0;
  int    tabsize = 0;
  int    tblstsiz = sizeof (struct tab_list);

  short  req_code;                    //cwe158646

  struct tab_list *tbhead = NULL;
  struct tab_list *currtb = NULL;

  //tabcnt = xmlplist->u.fr.fr_crt_nbr;
  tabcnt = xmlplist->u.fr.fr_fetch_cnt;
  tabsize = sizeof (struct tab_list) * tabcnt;
  tbhead = (struct tab_list *) malloc (tabsize);
  if (tbhead == NULL)
  {
    // couldn't get the memory
    return (RDXE506);
  }
  memset ((char *)tbhead, 0, tabsize);

  // for use in processing the input list later     cwe158646
  req_code = xmlplist->u.fr.frreq;                //cwe158646

  // ok, the multiblock data buffer has a bunch of pairs of strings
  // that are null terminated. the first of the strings is a creator
  // and the second is the table name. fire thru the data buffer
  // putting them respectively into
  if (xmlplist->xmlvrsn == 1)                               //CWE152292
  {
    for (i = 0,
         dptr = mb_data->buffer,
         currtb = tbhead; i < tabcnt; i++,
                                      currtb++)
    {
      currtb->obj_type = 'D';                               //CWE152292
      *db2_flag_1008_1009 = 'Y';                            //CWE152293
      // get creator, and skip ahead
      strcpy (currtb->db2.creator, dptr);
      dptr += strlen (dptr) + 1;

      // table name better be next
      strcpy (currtb->db2.tbname, dptr);
      dptr += strlen (dptr) +1;

      // set up linkages
      if (i == 0)
      {
        // set the head
        // tack tbhead onto return struct
        prmtbmet->tab_list = currtb;
      }

      if (i < (tabcnt - 1))
      {
        // all but last time
        currtb->next = (struct tab_list *) ((char *)currtb + tblstsiz);
      }
      if (i > 0)
      {
        // all but the first time
        currtb->prev = (struct tab_list *) ((char *)currtb - tblstsiz);
      }
    }
  }

  if (xmlplist->xmlvrsn == 2) //CWE152292 start
  {
    for (i = 0,
         dptr = mb_data->buffer,
         currtb = tbhead; i < tabcnt; i++,
                                      currtb++)
    {
      currtb->obj_type = *dptr;
      dptr += strlen (dptr) + 1;
      if (currtb->obj_type == 'D')
      {
        *db2_flag_1008_1009 = 'Y';                          //CWE152293
        // get creator, and skip ahead
        strcpy (currtb->db2.creator, dptr);
        dptr += strlen (dptr) + 1;

        // table name better be next
        strcpy (currtb->db2.tbname, dptr);
        dptr += strlen (dptr) +1;
      }
      if (currtb->obj_type == 'M')
      {
        // get layout
        strcpy (currtb->mvs.layout_dsn, dptr);
        dptr += strlen (dptr) + 1;

        // get 01 level
        // if we're doing 1009, we we won't have           cwe158646
        // an 01 level, so we only do this part            cwe158646
        // if we're doing 1008                             cwe158646
        if (req_code == 1008)                            //cwe158646
        {
          strcpy (currtb->mvs.level01_name, dptr);
          dptr += strlen (dptr) +1;
        }
      }

      // set up linkages
      if (i == 0)
      {
        // set the head
        // tack tbhead onto return struct
        prmtbmet->tab_list = currtb;
      }

      if (i < (tabcnt - 1))
      {
        // all but last time
        currtb->next = (struct tab_list *) ((char *)currtb + tblstsiz);
      }
      if (i > 0)
      {
        // all but the first time
        currtb->prev = (struct tab_list *) ((char *)currtb - tblstsiz);
      }
    }
  } //CWE152292 end
  return (0);
}

//
// dump the creator/table or mvs layout/01 level list
//
static void
//dmptbcr (struct prmtbmet *prmtbmet)                         CWE152293
dmpobjtbl (struct prmtbmet *prmtbmet)                       //CWE152293
{
  struct tab_list *currtb;
  struct tm       *wktime;
  time_t          wksecs;
  char            date_time[20];
  int             i;

  time (&wksecs);
  wktime = localtime (&wksecs);
  strftime (date_time, 20,"%Y/%m/%d %H:%M:%S", wktime);
  fprintf (xfrtrc, "\n%s XFRRSRVR: Creator & Tables, Layouts & 01 Levels (tab_li

  for (currtb = prmtbmet->tab_list, i = 0;
       currtb != NULL;
       currtb = currtb->next, i++)
  {
    // print creator & table names (& lengths)
    if (currtb->obj_type == 'D')                            //CWE152293
    {
      fprintf (xfrtrc, "\n%20.20s(%d) creator: '%s'", " ", i, currtb->db2.creato
      fprintf (xfrtrc, "\n%20.20s     tbname : '%s'", " ",    currtb->db2.tbname
    }
    if (currtb->obj_type == 'M')                            //CWE152293
    {
      fprintf (xfrtrc, "\n%20.20s(%d) layout : '%s'", " ", i, currtb->mvs.layout
      fprintf (xfrtrc, "\n%20.20s     01level: '%s'", " ",    currtb->mvs.level0
    }

    fprintf (xfrtrc, "\n%20.20s       next : '%p'", " ",    currtb->next);

  }
}

//
// dump some of the data for transactions 1008 & 1009
static void
dmptbmeta (struct prmtbmet *prmtbmet)
{
  struct tab_list *currtb;
  struct tm       *wktime;
  time_t          wksecs;
  char            date_time[20];
  int             i;

  time (&wksecs);
  wktime = localtime (&wksecs);
  strftime (date_time, 20,"%Y/%m/%d %H:%M:%S", wktime);

  if (prmtbmet->opcode == 1008)
  {
    fprintf (xfrtrc, "\n%s XFRRSRVR: METALIST (1st 100 bytes):", date_time);
    fprintf (xfrtrc, "\n%20.20s'%100s'", " ",prmtbmet->retstr);
  }
  else
  {
    fprintf (xfrtrc, "\n%s XFRRSRVR: Existence string (1st 50 bytes):", date_tim
    fprintf (xfrtrc, "\n%20.20s'%50.50s'", " ",prmtbmet->retstr);
  }
}

// -- added for cwe155431
// run through a list of relationships, looking for a cre/tbname
// pair. if we find it, return 1, if not return 0
//
static short
scanrels (struct Rel_Sel  *relhead,
          struct tab_list *tbptr)
{
  struct Rel_Sel      *relptr = NULL;
  struct Rel_Lst_Ent  *rele = NULL;
  MRT_V3              *mrt = NULL;
  MRT_ENTRY_V3        *mrte = NULL;
  short                found = 0;
  char                 loccre [CRTR_NAME_LGTH + 1];
  char                 loctab [TBL_NAME_LGTH + 1];

  memset (loccre, ' ', sizeof (loccre));
  memset (loctab, ' ', sizeof (loctab));
  memcpy (loccre, tbptr->db2.creator, strlen (tbptr->db2.creator));
  memcpy (loctab, tbptr->db2.tbname,  strlen (tbptr->db2.tbname));

  // we have a llist of llists, so we need 2 loops
  for (relptr = relhead;
       relptr != NULL;
       relptr = relptr->next)
  {
    for (rele = relptr->rel, found = 0;
         rele != NULL && !found;
         rele = rele->next)
    {
      mrte = (MRT_ENTRY_V3 *) rele->mrte;

      // check the rel elements
      if (mrte->parent_obj_type == 'D')
      {
        if (memcmp (loccre,
                    mrte->parent.db2_name.creator,
                    CRTR_NAME_LGTH) == 0 &&
            memcmp (loctab,
                    mrte->parent.db2_name.tbname,
                    TBL_NAME_LGTH) == 0 )
        {
          found = 1;
          break;
        }

        if (memcmp (loccre,
                    mrte->depend.db2_name.creator,
                    CRTR_NAME_LGTH) == 0 &&
            memcmp (loctab,
                    mrte->depend.db2_name.tbname,
                    TBL_NAME_LGTH) == 0 )
        {
          found = 1;
          break;
        }
      }
    }    // end of relptr loop

    if (found)
      break;
  } // end of outter loop

  // rel found?
  //fprintf (xfrtrc ...

  return found;
}

// added for   cwe155431
//
// add the rel info found in the prmraf onto the end of
// the Rel_Sel llist
static void
addrele (struct Rel_Sel      *relhead,
         struct Rel_Lst_Ent  *inrel)
{
  struct Rel_Sel *relptr = NULL;

  // do we have a real inrel?
  if (inrel == NULL)
    return;

  // skip to next to last element in relhead llist
  // (yes, this for loop has no body. I did that
  // on purpose)
  for (relptr = relhead;
       relptr->next != NULL;
       relptr = relptr->next);

  relptr->next = (struct Rel_Sel *) malloc (sizeof (struct Rel_Sel));
  relptr = relptr->next;
  relptr->rel = inrel;

  return;
}


static short
Convert_to_Hex(char *hex_out, char *char_in, short len)
{
  char       nybble[] = "0123456789ABCDEF";
  char      *ptr;
  char      *in_ptr;
  char      *out_ptr;
  char       no_data_yet = 1;
  short      out_len, w_len;
  short      wrk_char;
  short      wrk1, wrk2;

  out_len = len * 2;
  out_ptr = hex_out + out_len;
  w_len = len;
  memset(hex_out, '\0', out_len);
  ptr = char_in + w_len - 1;

  for (; w_len>0; w_len--, ptr--)                 //D0018369
  {
    out_ptr -= 2;
    if ((*ptr == ' ' || *ptr == '\0') && no_data_yet)
    {
      out_len -= 2;
      continue;
    }

    no_data_yet = 0;
    wrk_char = *ptr;
    wrk1 = wrk_char / 16;
    wrk2 = wrk_char - wrk1 * 16;
    *out_ptr = nybble[wrk1];
    *(out_ptr+1) = nybble[wrk2];
  }
  return out_len;
}

//                     cwe155431
static void
dmprelhd (struct Rel_Sel *relhead)
{
  struct Rel_Sel      *rsptr;
  struct Rel_Lst_Ent  *reptr;
  struct Mrt_Entry_V3 *mrte;
  int                  i, j;

  fprintf (xfrtrc, "\n rel head dump:");

  for (rsptr = relhead, i = 1; rsptr != NULL; rsptr = rsptr->next, i++)
  {
    fprintf (xfrtrc, "\n rel_sel #%d     next : %p", i, rsptr->next);

    for (reptr = rsptr->rel, j = 1; reptr != NULL; reptr = reptr->next, j++)
    {
      fprintf (xfrtrc, "\n   rel_ent #%d     next : %p", j, reptr->next);


      mrte = (struct Mrt_Entry_V3 *) reptr->mrte;

      fprintf (xfrtrc, "\n        mrte rel name: %10.10s", mrte->rel_description
      fprintf (xfrtrc, "\n               -- par cre %10.10s -- par tab -- %20.20
               mrte->parent.db2_name.creator, mrte->parent.db2_name.tbname);
      fprintf (xfrtrc, "\n               -- dep cre %10.10s -- dep tab -- %20.20
               mrte->depend.db2_name.creator, mrte->depend.db2_name.tbname);
    }
  }

}

static void
dmphex (char *instr,
        int   len)
{
  short offset;
  char  prt_line[132];
  char  wrk_area[9];
  int  *d_ptr;
  char *d1_ptr;
  char *pl_ptr;
  char  w_char;
  short i,j;

      // dump some memory
  d_ptr = (int *) instr;
  d1_ptr = (char *) instr;
  fprintf (xfrtrc, "\n             %d bytes of data:", len);

  for (offset = 0; offset < len; offset += 32)
  {
    memset (prt_line, ' ', 132);
    sprintf (wrk_area, "%4.4X", offset);
    memcpy (prt_line, wrk_area, 4);
    pl_ptr = prt_line;
    pl_ptr += 5;

    for (i = 1; i <= 2; i++)
    {
      pl_ptr += 3;
      for (j = 0; j < 4; j++, d_ptr++, pl_ptr += 9)
      {
        sprintf (wrk_area, "%8.8X", *d_ptr);
        memcpy (pl_ptr, wrk_area, 8);
      }
    }

    pl_ptr += 2;
    *pl_ptr = '*';
    pl_ptr++;

    for (i = 1; i <= 32; i++, pl_ptr++, d1_ptr++)
    {
      w_char = *d1_ptr;
      if (w_char >= ' ')
        *pl_ptr = w_char;
      else
        *pl_ptr = '.';
    }

    *pl_ptr = '*';
    fprintf (xfrtrc, "\n%-132.132s", prt_line);
  }
}