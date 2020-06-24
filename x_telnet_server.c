/*
 * x_telnet_server.c - Telnet protocol support
 */

#include	"x_config.h"
#include	"FreeRTOS_Support.h"
#include	"x_telnet_server.h"
#include	"task_control.h"

#include	"commands.h"
#include	"x_authenticate.h"
#include	"x_errors_events.h"
#include	"syslog.h"
#include	"printfx.h"
#include	"x_terminal.h"
#include	"x_retarget.h"

#include	"hal_debug.h"

#include	<unistd.h>
#include	<string.h>
#include	<sys/errno.h>

/* Documentation links
 * Obsolete:
 * 		https://tools.ietf.org/html/rfc698
 * Current:
 * 		https://tools.ietf.org/html/rfc854
 * 		https://tools.ietf.org/html/rfc5198
 */

// ############################### BUILD: debug configuration options ##############################

#define	debugFLAG						0xC003

#define	debugOPTIONS					(debugFLAG & 0x0001)
#define	debugSTATE						(debugFLAG & 0x0002)

#define	debugTRACK						(debugFLAG & 0x2000)
#define	debugPARAM						(debugFLAG & 0x4000)
#define	debugRESULT						(debugFLAG & 0x8000)

// ##################################### Private/Static variables ##################################

const char * codename[4] = {"WILL", "WONT", "DO", "DONT"} ;

opts_t options = {
	.val[0] = tnetOPT_ECHO, 	.name[0] = "Echo",
	.val[1] = tnetOPT_SGA,		.name[1] = "SGA",
	.val[2] = tnetOPT_TTYPE,	.name[2] = "TType",
	.val[3] = tnetOPT_NAWS,		.name[3] = "NaWS",
	.val[4] = tnetOPT_TSPEED,	.name[4] = "TSPeed",
	.val[5] = tnetOPT_LMODE,	.name[5] = "LMode",
	.val[6] = tnetOPT_OLD_ENV,	.name[6] = "Oenv",
	.val[7] = tnetOPT_NEW_ENV,	.name[7] = "Nenv",
	.val[8] = tnetOPT_STRT_TLS, .name[8] = "STLS",
	.val[9] = tnetOPT_UNDEF,	.name[9] = "Oxx",
} ;

// ####################################### Public Variables ########################################

static netx_t	sServTNetCtx = { 0 } ;
static tnet_con_t	sTerm = { 0 } ;
static uint8_t		TNetState ;
static uint8_t		TNetSubSt ;

// ####################################### private functions #######################################

void	vTelnetDeInit(int32_t eCode) {
	xNetClose(&sTerm.sCtx) ;
	xRtosClearStatus(flagNET_TNET_CLNT) ;
	sTerm.Running = 0 ;

	xNetClose(&sServTNetCtx) ;
	xRtosClearStatus(flagNET_TNET_SERV) ;
	TNetState = tnetSTATE_INIT ;
	IF_CTRACK(debugTRACK, "deinit: err=%d '%s'",  eCode, strerror(eCode)) ;
}

const char * xTelnetFindName(uint8_t opt) {
	uint8_t idx ;
	for (idx = 0; options.val[idx] != tnetOPT_UNDEF; ++idx) {
		if (options.val[idx] == opt) {
			break ;
		}
	}
	return options.name[idx] ;
}

/**
 * xTelnetSetOption() - store the value (WILL/WONT/DO/DONT) for a specific option.
 * @param option	ECHO ... START_TLS
 * @param code		WILL / WONT / DO / DONT
 */
void	xTelnetSetOption(uint8_t opt, uint8_t cmd) {
	IF_myASSERT(debugPARAM, INRANGE(tnetWILL, cmd, tnetDONT, uint8_t) && INRANGE(tnetOPT_ECHO, opt, tnetOPT_STRT_TLS, uint8_t)) ;
	uint8_t	Xidx = opt / 4 ;							// 2 bits/value, 4 options/byte
	uint8_t	Sidx = (opt % 4) * 2 ;						// positions (0/2/4/6) to shift mask & value left
	sTerm.options[Xidx]	&=  0x03 << Sidx ;
	sTerm.options[Xidx]	|= (cmd - tnetWILL) << Sidx ;
	IF_CPRINT(debugOPTIONS, " -> %s\n", codename[cmd - tnetWILL]) ;
}

/**
 * xTelnetGetOption() - retrieve the value (WILL/WONT/DO/DONT) for a specific option.
 * @param option	ECHO ... START_TLS
 * @return code		WILL / WONT / DO / DONT
 */
uint8_t	xTelnetGetOption(uint8_t opt) {
	IF_myASSERT(debugPARAM, INRANGE(tnetOPT_ECHO, opt, tnetOPT_STRT_TLS, uint8_t)) ;
	return (sTerm.options[opt/4] >> ((opt % 4) * 2)) & 0x03  ;
}

void	vTelnetUpdateStats(void) {
	if (sServTNetCtx.maxTx < sTerm.sCtx.maxTx) {
		sServTNetCtx.maxTx = sTerm.sCtx.maxTx ;
	}
	if (sServTNetCtx.maxRx < sTerm.sCtx.maxRx) {
		sServTNetCtx.maxRx = sTerm.sCtx.maxRx ;
	}
}

int32_t	xTelnetHandleSGA(void) {
	int32_t iRV = xTelnetGetOption(tnetOPT_SGA) ;
	if (iRV == valDONT || iRV == valWONT) {
		char cGA = tnetGA ;
		iRV = xNetWrite(&sTerm.sCtx, &cGA, sizeof(cGA)) ;
		if (iRV != sizeof(cGA)) {
			vTelnetDeInit(iRV) ;
			return erFAILURE ;
		}
	}
	return erSUCCESS ;
}

/**
 * xTelnetFlushBuf() -- send any/all buffered data immediately after connection established
 * @return		non-zero positive value if nothing to send or all successfully sent
 *				0 (if socket closed) or other negative error code
 */
int32_t	xTelnetFlushBuf(void) {
	if ((xUBufAvail(&sRTCslow.sBufStdOut) == 0) ||		// no characters there; OR
		bRtosCheckStatus(flagNET_TNET_SERV | flagNET_TNET_CLNT) == false) { // server or client not running
		return erSUCCESS ;
	}
	int32_t	iRV	= sRTCslow.sBufStdOut.IdxWR > sRTCslow.sBufStdOut.IdxRD ? sRTCslow.sBufStdOut.IdxWR - sRTCslow.sBufStdOut.IdxRD :	// single block
				  sRTCslow.sBufStdOut.IdxWR < sRTCslow.sBufStdOut.IdxRD ? sRTCslow.sBufStdOut.Size - sRTCslow.sBufStdOut.IdxRD	:	// possibly 2 blocks
				  0 ;																			// nothing
#if		(configBUILD_WITH_NEW_CODE  == 1)
	if (iRV) {											// anything to write ?
		iRV = xNetWrite(&sTerm.sCtx, pcUBufTellRead(&sRTCslow.sBufStdOut), iRV) ;	// yes, write #1
		vTelnetUpdateStats() ;
		if ((iRV > 0) && 								// if #1 write successful AND
			(sRTCslow.sBufStdOut.IdxWR < sRTCslow.sBufStdOut.IdxRD) && 	// possibly #2 required AND
			(sRTCslow.sBufStdOut.IdxWR > 0)) {			// something there for #2
			iRV = xNetWrite(&sTerm.sCtx, (char *) sRTCslow.sBufStdOut.pBuf, sRTCslow.sBufStdOut.IdxWR) ;	// write #2 of 2
			vTelnetUpdateStats() ;
		}
		xTelnetHandleSGA() ;							// if req, send GA
	}
	vUBufReset(&sRTCslow.sBufStdOut) ;					// reset pointers to reflect empty
#else
	if (iRV) {											// anything to write ?
		iRV = xNetWrite(&sTerm.sCtx, pcUBufTellRead(&sRTCslow.sBufStdOut), iRV) ;	// yes, write #1
		vTelnetUpdateStats() ;
		if ((iRV > 0) && 								// if #1 write successful AND
			(sRTCslow.sBufStdOut.IdxWR < sRTCslow.sBufStdOut.IdxRD) && 	// possibly #2 required AND
			(sRTCslow.sBufStdOut.IdxWR > 0)) {					// something there for #2
			iRV = xNetWrite(&sTerm.sCtx, (char *) sRTCslow.sBufStdOut.pBuf, sRTCslow.sBufStdOut.IdxWR) ;	// write #2 of 2
			vTelnetUpdateStats() ;
		}
	}
	xTelnetHandleSGA() ;								// if req, send GA
	vUBufReset(&sRTCslow.sBufStdOut) ;					// reset pointers to reflect empty
#endif

	if (iRV < erSUCCESS) {
		TNetState = tnetSTATE_DEINIT ;
	}
	return iRV < erSUCCESS ? iRV : erSUCCESS ;
}

/**
 * xTelnetSendOptions() - send a single option to the client
 * @param o1	Option
 * @param o2	Value
 * @return		erSUCCESS or (-) error code or (+) number of bytes (very unlikely)
 */
void	vTelnetSendOption(uint8_t opt, uint8_t cmd) {
	char cBuf[3] = { tnetIAC, cmd, opt } ;
	int32_t iRV = xNetWrite(&sTerm.sCtx, cBuf, sizeof(cBuf)) ;
	if (iRV == sizeof(cBuf)) {
		xTelnetSetOption(opt, cmd) ;
		vTelnetUpdateStats() ;
	} else {
		vTelnetDeInit(iRV) ;
	}
}

/**
 * xTelnetNegotiate()
 * @param code
 * @param option
 * @return		erSUCCESS or (-) error code or
 *
 *	http://users.cs.cf.ac.uk/Dave.Marshall/Internet/node141.html
 *
 *							-------	Sent if -------
 *	Received	Type		Agree		DisAgree
 *	WILL		Offer		DO			DONT
 *	WONT		Offer		DONT		DO
 *	DO			Desire		WILL		WONT
 *	DONT		Desire		WONT		WILL
 *
 * Telnet, as in MikroTik RouterOS, offer the following
 *	Do SGA
 *	Will TTYPE, NAWS, TSPEED, Remote Flow Control, LMODE, NEWENV
 *	Do Status
 */
void	vTelnetNegotiate(uint8_t opt, uint8_t cmd) {
	IF_CPRINT(debugOPTIONS, "%02d/%s = %s", opt, xTelnetFindName(opt), codename[cmd-tnetWILL]) ;
	switch (opt) {
	case tnetOPT_ECHO:		// Client must not (DONT) and server WILL
		vTelnetSendOption(opt, (cmd == tnetWILL || cmd == tnetWONT) ? tnetDONT : tnetWILL) ;
		break ;

	case tnetOPT_SGA:		// Client must (DO) and server WILL
		vTelnetSendOption(opt, (cmd == tnetWILL || cmd == tnetWONT) ? tnetDO : tnetWILL) ;
		break ;

#if		(buildTERMINAL_CONTROLS_CURSOR == 1)
	case tnetOPT_NAWS:									// can have functionality
		vTelnetSendOption(opt, cmd==tnetWILL ? tnetDO : cmd==tnetWONT ? tnetDONT : cmd==tnetDO ? tnetWILL : tnetWONT) ;
		break ;
#endif

	default:		// Client WILL/WONT, but Server DONT  <ALT>  Client DO/DONT but Server WONT
		vTelnetSendOption(opt, cmd==tnetWILL || cmd==tnetWONT ? tnetDONT : tnetWONT) ;
	}
}

void	vTelnetUpdateOption(void) {
	switch (sTerm.code) {
	case tnetOPT_NAWS:
		if (sTerm.optlen == 4) {
#if		(buildTERMINAL_CONTROLS_CURSOR == 1)		// NOT TESTED, check against RFC
			vTerminalSetSize(ntohs(*(unsigned short *) sTerm.optdata), ntohs(*(unsigned short *) (sTerm.optdata + 2))) ;
			IF_CPRINT(debugOPTIONS, "Applied NAWS C=%d R=%d\n", ntohs(*(unsigned short *) sTerm.optdata), ntohs(*(unsigned short *) (sTerm.optdata + 2))) ;
#else
			SL_INFO("Ignored NAWS C=%d R=%d", ntohs(*(unsigned short *) sTerm.optdata), ntohs(*(unsigned short *) (sTerm.optdata + 2))) ;
#endif
		} else {
			SL_ERR("Ignored NAWS Len %d != 4", sTerm.optlen ) ;
		}
		break ;
	default:
		SL_ERR("Unsupported OPTION %d data (%d bytes)", sTerm.code, sTerm.optlen) ;
	}
}

int32_t	xTelnetParseChar(int32_t cChr) {
	switch (TNetSubSt) {
	case tnetSUBST_CHECK:
#if		(configBUILD_WITH_NEW_CODE == 1)
		if (cChr == tnetIAC)
			TNetSubSt = tnetSUBST_IAC ;
		else if (cChr != tnetGA)
			return cChr ;								// RETURN the character
		break ;
#else
		if (cChr == tnetIAC) 		{ TNetSubSt = tnetSUBST_IAC ;	}
		else if (cChr == tnetGA)	{ return erSUCCESS ;			}
		else						{ return cChr ;					}					// RETURN the character
		break ;
#endif
	case tnetSUBST_IAC:
		switch (cChr) {
		case tnetSB:	TNetSubSt	= tnetSUBST_SB ;							break ;
		case tnetWILL:
		case tnetWONT:
		case tnetDO:
		case tnetDONT:	sTerm.code	= cChr ;	TNetSubSt = tnetSUBST_OPT ;		break ;
		case tnetIAC:	TNetSubSt	= tnetSUBST_CHECK ;							return cChr ;	// RETURN 2nd IAC
		default:		TNetSubSt	= tnetSUBST_CHECK ;							IF_myASSERT(debugSTATE, 0) ;
		}
		break ;
	case tnetSUBST_SB:	sTerm.code	= cChr ; sTerm.optlen = 0 ;	TNetSubSt = tnetSUBST_OPTDAT ;	break ;	// option ie NAWS, SPEED, TYPE etc
	case tnetSUBST_OPT:	vTelnetNegotiate(cChr, sTerm.code) ;	TNetSubSt = tnetSUBST_CHECK ;	break ;
	case tnetSUBST_OPTDAT:
		if (cChr == tnetIAC) {
			TNetSubSt = tnetSUBST_SE ;
		} else if (sTerm.optlen < sizeof(sTerm.optdata)) {
			sTerm.optdata[sTerm.optlen++] = cChr ;
		} else {
			IF_myASSERT(debugSTATE, 0) ;
		}
		break ;
	case tnetSUBST_SE:
		if (cChr == tnetSE) {
			vTelnetUpdateOption() ;
			TNetSubSt = tnetSUBST_CHECK ;
			break ;
		}
		/* FALLTHRU */
	default:
		IF_myASSERT(debugSTATE, 0) ;
	}
	return erSUCCESS ;
}

int32_t	xTelnetSetBaseline(void) {
	/*					Putty			MikroTik
	 *	WONT	DONT	no echo			local echo
	 *	WILL	DONT	no echo			no echo
	 */
	int32_t iRV = xTelnetGetOption(tnetOPT_ECHO) ;
	if (iRV == valWILL || iRV == valDONT) {
		vTelnetSendOption(tnetOPT_ECHO, tnetDONT) ;
		vTelnetSendOption(tnetOPT_ECHO, tnetWILL) ;
	}
	/*					Putty			MikroTik
	 *	WONT	DONT	working			not working
	 *	WILL	DONT	not working		not working
	 *	WONT	DO		not working		not working
	 *	WILL	DO		not working		not working
	 */
	iRV = xTelnetGetOption(tnetOPT_SGA) ;
	if (iRV == valWONT || iRV == valDONT) {
		vTelnetSendOption(tnetOPT_SGA, tnetDO) ;
		vTelnetSendOption(tnetOPT_SGA, tnetWILL) ;
	}
	return erSUCCESS ;
}

// ################### global functions, normally running in other task context ####################

/**
 * vTelnetTask()
 * @param pvParameters
 */
void	vTaskTelnet(void *pvParameters) {
	IF_CTRACK(debugAPPL_THREADS, debugAPPL_MESS_UP) ;
	int32_t	iRV = 0 ;
	char cChr ;
	TNetState = tnetSTATE_INIT ;
	xRtosSetStateRUN(taskTELNET) ;

	while (bRtosVerifyState(taskTELNET)) {
		if (TNetState != tnetSTATE_DEINIT) {
			xRtosWaitStatusANY(flagL3_ANY, portMAX_DELAY) ;
		}
		switch(TNetState) {
		case tnetSTATE_DEINIT:
			vTelnetDeInit(iRV) ;
			break ;					// must NOT fall through since the Lx status might have changed

		case tnetSTATE_INIT:
			IF_CTRACK(debugTRACK, "Init Start") ;
			memset(&sServTNetCtx, 0 , sizeof(sServTNetCtx)) ;
			sServTNetCtx.sa_in.sin_family	= AF_INET ;
			sServTNetCtx.type				= SOCK_STREAM ;
			sServTNetCtx.sa_in.sin_port		= htons(IP_PORT_TELNET) ;
			sServTNetCtx.flags				|= SO_REUSEADDR ;
		#if 0
			sServTNetCtx.d_open				= 1 ;
			sServTNetCtx.d_read				= 1 ;
			sServTNetCtx.d_write			= 1 ;
			sServTNetCtx.d_close			= 1 ;
			sServTNetCtx.d_accept			= 1 ;
			sServTNetCtx.d_select			= 1 ;
		#endif
			iRV = xNetOpen(&sServTNetCtx) ;			// default blocking state
			if (iRV < erSUCCESS) {
				TNetState = tnetSTATE_DEINIT ;
				IF_CTRACK(debugTRACK, "OPEN fail") ;
				vTaskDelay(pdMS_TO_TICKS(tnetMS_OPEN)) ;
				break ;
			}
			xRtosSetStatus(flagNET_TNET_SERV) ;
			memset(&sTerm, 0, sizeof(tnet_con_t)) ;
			TNetState = tnetSTATE_WAITING ;
			IF_CTRACK(debugTRACK, "Init OK, waiting") ;
			/* FALLTHRU */

		case tnetSTATE_WAITING:
			iRV = xNetAccept(&sServTNetCtx, &sTerm.sCtx, tnetMS_ACCEPT) ;
			if (iRV < erSUCCESS) {
				if ((sServTNetCtx.error != EAGAIN) &&
					(sServTNetCtx.error != ECONNABORTED)) {
					iRV = sServTNetCtx.error ;
					TNetState = tnetSTATE_DEINIT ;
					IF_CTRACK(debugTRACK, "ACCEPT failed") ;
				}
				break ;
			}
			xRtosSetStatus(flagNET_TNET_CLNT) ;

			// setup timeout for processing options
			iRV = xNetSetRecvTimeOut(&sTerm.sCtx, tnetMS_OPTIONS) ;
			if (iRV != erSUCCESS) {
				TNetState = tnetSTATE_DEINIT ;
				IF_CTRACK(debugTRACK, "Receive tOut failed") ;
				break ;
			}
			TNetState = tnetSTATE_OPTIONS ;			// and start processing options
			TNetSubSt = tnetSUBST_CHECK ;
			IF_CTRACK(debugTRACK, "Accept OK") ;
			xTelnetSetBaseline() ;
			IF_CTRACK(debugTRACK, "Baseline sent") ;
			/* FALLTHRU */

		case tnetSTATE_OPTIONS:
			iRV = xNetRead(&sTerm.sCtx, &cChr, sizeof(cChr)) ;
			if (iRV != sizeof(cChr)) {
				if (sTerm.sCtx.error != EAGAIN) {	// socket closed or error (excl EAGAIN)
					iRV = sTerm.sCtx.error ;
					TNetState = tnetSTATE_DEINIT ;
					break ;
				}
				/* EAGAIN so unless completed OPTIONS phase (tnetSUBST_CHECK) try again */
				if (TNetSubSt != tnetSUBST_CHECK) {
					break ;
				}
			} else {
				if (xTelnetParseChar(cChr) == erSUCCESS) {
					break ;
				}
				/* still in OPTIONS, read a character, was NOT parsed as a valid OPTION char, then HWHAP !!! */
				IF_myASSERT(debugSTATE && TNetSubSt != tnetSUBST_CHECK, 0) ;
			}
			// setup timeout for processing normal comms
			if ((iRV = xNetSetRecvTimeOut(&sTerm.sCtx, tnetMS_READ_WRITE)) != erSUCCESS) {
				TNetState = tnetSTATE_DEINIT ;
				break ;
			}
			TNetState = tnetSTATE_AUTHEN ;				// no char, start authenticate
			TNetSubSt = tnetSUBST_CHECK ;
			IF_CTRACK(debugTRACK, "Options OK") ;
			/* FALLTHRU */

		case tnetSTATE_AUTHEN:
#if		(tnetAUTHENTICATE == 1) || (configPRODUCTION == 1)
			if (xAuthenticate(sTerm.sCtx.sd, configUSERNAME, configPASSWORD, true) != erSUCCESS) {
				if (errno != EAGAIN) {
					iRV = errno ;
					TNetState = tnetSTATE_DEINIT ;
				}
				break ;
			}
			IF_CTRACK(debugTRACK, "Authentication OK") ;
#endif
			// All options and authentication done, empty the buffer to the client
			if (xTelnetFlushBuf() != erSUCCESS) {
				iRV = errno ;
				TNetState = tnetSTATE_DEINIT ;
				break ;
			}
			TNetState = tnetSTATE_RUNNING ;
			/* FALLTHRU */

		case tnetSTATE_RUNNING:
			// Step 0: if anything there from an earlier background event, display it...
			xStdOutLock(portMAX_DELAY) ;
			vCommandInterpret(CHR_NUL, true) ;			// force checking of flags
			xTelnetFlushBuf() ;
			xStdOutUnLock() ;
			// Step 1: read a single character
			iRV = xNetRead(&sTerm.sCtx, &cChr, sizeof(cChr)) ;
			if (iRV != sizeof(cChr)) {
				if (sTerm.sCtx.error != EAGAIN) {		// socket closed or error (but not EAGAIN)
					iRV = sTerm.sCtx.error ;
					TNetState = tnetSTATE_DEINIT ;
				}
				break ;
			}
			// Step 2: check if not part of Telnet negotiation
			if (xTelnetParseChar(cChr) == erSUCCESS) {
				break ;
			}
			// Step 3: Handle special (non-Telnet) characters
			if (cChr == CHR_GS) {						// cntl + ']'
				iRV = EOF ;
				TNetState = tnetSTATE_DEINIT ;
				break ;
			}
			// Step 4: must be a normal command character, process as if from UART console....
			xStdOutLock(portMAX_DELAY) ;
			vCommandInterpret(cChr, true) ;
			xTelnetFlushBuf() ;
			xStdOutUnLock() ;
			break ;

		default:
			IF_myASSERT(debugSTATE, 0) ;
		}
	}
	xTelnetFlushBuf() ;
	vTelnetDeInit(0) ;
	IF_CTRACK(debugAPPL_THREADS, debugAPPL_MESS_DN) ;
	vTaskDelete(NULL) ;
}

void	vTaskTelnetInit(void) { xRtosTaskCreate(vTaskTelnet, "TNET", tnetSTACK_SIZE, 0, tnetPRIORITY, NULL, INT_MAX) ; }

void	vTelnetReport(void) {
	if (bRtosCheckStatus(flagNET_TNET_CLNT)) {
		xNetReport(&sTerm.sCtx, "TNETclt", 0, 0, 0) ;
	}
	if (bRtosCheckStatus(flagNET_TNET_SERV)) {
		xNetReport(&sServTNetCtx, "TNETsrv", 0, 0, 0) ;
	} else {
		PRINT("%CTNETxxx%C\t", xpfSGR(attrRESET, colourFG_CYAN, 0, 0), attrRESET) ;
	}
#if		(debugOPTIONS)
	for (int32_t idx = tnetOPT_ECHO; idx < tnetOPT_MAX_VAL; ++idx) {
		PRINT("%d/%s=%s ", idx, xTelnetFindName(idx), codename[xTelnetGetOption(idx)]) ;
	}
	PRINT("\n") ;
#endif
#if		(buildTERMINAL_CONTROLS_CURSOR == 1)
	terminfo_t	TermInfo ;
	vTerminalGetInfo(&TermInfo) ;
	PRINT("WinInfo\tCx=%d  Cy=%d  Mx=%d  My=%d\n", TermInfo.CurX, TermInfo.CurY, TermInfo.MaxX, TermInfo.MaxY) ;
#endif
	PRINT("\tFSM=%d  maxTX=%u  maxRX=%u\n", TNetState, sServTNetCtx.maxTx, sServTNetCtx.maxRx) ;
}
