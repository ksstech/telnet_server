/*
 * x_telnet_server.c - Telnet protocol support
 */

#include	"x_config.h"

#if		(configCONSOLE_TELNET == 1)
#include	"x_telnet_server.h"
#include	"x_authenticate.h"
#include	"task_console.h"
#include	"x_debug.h"
#include	"x_errors_events.h"
#include	"x_syslog.h"
#include	"x_terminal.h"
#include	"x_retarget.h"

#include	<unistd.h>
#include	<string.h>

// ############################### BUILD: debug configuration options ##############################

#define	debugFLAG						0x0000
#define	debugPARAM						(debugFLAG & 0x0001)
#define	debugTRACK						(debugFLAG & 0x0002)
#define	debugRESULT						(debugFLAG & 0x0004)

#define	TRACK_FORMAT	"@%d iRV=%d"

// ######################################### enumerations ##########################################


// ####################################### Public Variables ########################################

sock_ctx_t	sServTNetCtx = { 0 } ;
tnet_con_t	sTerm = { 0 } ;
uint8_t		TNetState ;

// ####################################### private functions #######################################

void	vTelnetUpdateStats(void) {
	// Update the TX & RX max sizes
	if (sServTNetCtx.maxTx < sTerm.sCtx.maxTx) {
		sServTNetCtx.maxTx = sTerm.sCtx.maxTx ;
	}
	if (sServTNetCtx.maxRx < sTerm.sCtx.maxRx) {
		sServTNetCtx.maxRx = sTerm.sCtx.maxRx ;
	}
}

/**
 * xTelnetFlushBuf() -- send any/all buffered data immediately after connection established
 * @return		non-zero positive value if nothing to send or all successfully sent
 *				0 (if socket closed) or other negative error code
 */
int32_t	xTelnetFlushBuf(void) {
	if (xRtosCheckStatus(flagNET_TNET_SERV | flagNET_TNET_CLNT) == 0) {
		return 1 ;
	}
	int32_t	iRetVal	= sBufStdOut.IdxWR > sBufStdOut.IdxRD ?
					  sBufStdOut.IdxWR - sBufStdOut.IdxRD :		// single block
					  sBufStdOut.IdxWR < sBufStdOut.IdxRD ?
					  sBufStdOut.Size - sBufStdOut.IdxRD : 0 ;	// possibly 2 blocks..

	if (iRetVal > 0) {											// anything to write ?
		iRetVal = xNetWrite(&sTerm.sCtx, pcUBufTellRead(&sBufStdOut), iRetVal) ;	// yes, write #1
		if ((iRetVal > 0) && 									// if #1 write successful AND
			(sBufStdOut.IdxWR < sBufStdOut.IdxRD) && 			// possibly #2 required AND
			(sBufStdOut.IdxWR > 0)) {							// something there for #2
			iRetVal = xNetWrite(&sTerm.sCtx, (char *) sBufStdOut.pBuf, sBufStdOut.IdxWR) ;	// write #2 of 2
		}
	} else {
		iRetVal = 1 ;
	}
	sBufStdOut.Used	= sBufStdOut.IdxWR = sBufStdOut.IdxRD = 0 ;	// reset pointers to reflect empty
	vTelnetUpdateStats() ;
	return iRetVal ;
}

int32_t	xTelnetSendOptions(uint8_t o1, uint8_t o2) {
	char cBuf[3] ;
	cBuf[0] = telnetIAC ;
	cBuf[1] = o1 ;
	cBuf[2] = o2 ;
	int32_t iRetVal = xNetWrite(&sTerm.sCtx, cBuf, sizeof(cBuf)) ;
	if (iRetVal != sizeof(cBuf)) {
		IF_SL_DBG(debugRESULT, TRACK_FORMAT, __LINE__, iRetVal) ;
		return iRetVal ;
	}
	vTelnetUpdateStats() ;
	return iRetVal ;
}

static const char cTelnetOptions[] = {
	telnetIAC,	telnetWILL,	telnetOPT_ECHO,
	telnetIAC,	telnetWILL, telnetOPT_SUP_GOAHEAD,
	telnetIAC,	telnetWONT, telnetOPT_LINEMODE,
	telnetIAC,	telnetDO,	telnetOPT_NAWS,
} ;

int32_t	xTelnetSendDefaultOptions(void) {
	int32_t iRetVal = xNetWrite(&sTerm.sCtx, (char *) cTelnetOptions, sizeof(cTelnetOptions)) ;
	if (iRetVal != sizeof(cTelnetOptions)) {
		IF_SL_DBG(debugRESULT, "iRV=%d", iRetVal) ;
	}
	vTelnetUpdateStats() ;
	return iRetVal ;
}

/**
 * xTelnetParseOpt()
 * @param code
 * @param option
 * @return		erSUCCESS of EOF
 */
int32_t	xTelnetParseOpt(int code, int option) {
#if		(debugTRACK)
	static char *codename[4] = {"WILL", "WONT", "DO", "DONT"} ;
	PRINT("%s %d\n", codename[code - 251], option) ;
#endif
	switch (option) {
	case telnetOPT_SUP_GOAHEAD:
		if (code == telnetWONT) {
			sTerm.SupGA = 0 ;
		}
		break ;
	case telnetOPT_ECHO:
	case telnetOPT_NAWS:
		break;

	case telnetOPT_TERM_TYPE:
	case telnetOPT_TERM_SPD:
		return xTelnetSendOptions(telnetDO, option);

	default:
		if (code == telnetWILL || code == telnetWONT) {
			return xTelnetSendOptions(telnetDONT, option);
		}
		return xTelnetSendOptions(telnetWONT, option);
	}
	return erSUCCESS ;
}

void	vTelnetParseOptDat(int option, unsigned char *data, int len) {
	IF_PRINT(debugTRACK, "OPTION %d data (%d bytes)\n", option, len) ;

	switch (option) {
	case telnetOPT_TERM_TYPE:	IF_PRINT(debugTRACK, "TERMINAL TYPE %*s\n", len, data);		break;
	case telnetOPT_NAWS:
		if (len == 4) {
#if		(buildTERMINAL_CONTROLS_CURSOR == 1)
			vTerminalSetSize(ntohs(*(unsigned short *) data), ntohs(*(unsigned short *) (data + 2))) ;
#endif
		}
		break;

	case telnetOPT_TERM_SPD:	IF_PRINT(debugTRACK, "TERMINAL SPEED %*s\n", len, data);	break;

	}
}

int32_t	xTelnetParseChar(int32_t c) {
	switch (TNetState) {
	case stateTELNET_OPTIONS:
		if (c == telnetIAC) {
			TNetState = stateTELNET_IAC ;
		} else {
			return c ;
		}
		break;

	case stateTELNET_IAC:
		switch (c) {
		case telnetIAC:
			TNetState = stateTELNET_OPTIONS ;
			return c ;

		case telnetWILL:
		case telnetWONT:
		case telnetDO:
		case telnetDONT:
			sTerm.code = c ;
			TNetState = stateTELNET_OPT ;
			break;

		case telnetSB:
			TNetState = stateTELNET_SB ;
			break;

		default:
			TNetState = stateTELNET_OPTIONS ;
		}
		break;

	case stateTELNET_OPT:
		TNetState = stateTELNET_OPTIONS ;
		return xTelnetParseOpt(sTerm.code, c) ;

	case stateTELNET_SB:
		sTerm.code = c ;
		sTerm.optlen = 0 ;
		TNetState = stateTELNET_OPTDAT ;
		break ;

	case stateTELNET_OPTDAT:
		if (c == telnetIAC) {
			TNetState = stateTELNET_SE ;
		} else if (sTerm.optlen < sizeof(sTerm.optdata)) {
			sTerm.optdata[sTerm.optlen++] = c ;
		}
		break;

	case stateTELNET_SE:
		if (c == telnetSE) {
			vTelnetParseOptDat(sTerm.code, sTerm.optdata, sTerm.optlen) ;
			sTerm.optlen = 0 ;
		}
		TNetState = stateTELNET_OPTIONS ;
		break;
	}
	return -1 ;
}

// ################### global functions, normally running in other task context ####################

void	vTelnetCloseClient(void) {
	vRtosClearStatus(flagNET_TNET_CLNT | flagNET_AUTHENTICATED) ;
	TNetState = stateTELNET_WAITING ;
	xNetClose(&sTerm.sCtx) ;
}

void	vTelnetDeInit(void) {
	vRtosClearStatus(flagNET_TNET_SERV | flagNET_AUTHENTICATED) ;
	vTelnetCloseClient() ;
	xNetClose(&sServTNetCtx) ;
	TNetState = stateTELNET_INIT ;
	IF_SL_DBG(debugTRACK, "deinit") ;
}

void	vTelnetInit(void) {
	IF_SL_DBG(debugTRACK, "init") ;
	memset(&sServTNetCtx, 0 , sizeof(sServTNetCtx)) ;
	sServTNetCtx.sa_in.sin_family	= AF_INET ;
	sServTNetCtx.type				= SOCK_STREAM ;
	sServTNetCtx.sa_in.sin_port		= htons(IP_PORT_TELNET) ;
	sServTNetCtx.flags				|= SO_REUSEADDR ;
#if 0
	sServTNetCtx.d_open				= 1 ;
	sServTNetCtx.d_read				= 1 ;
	sServTNetCtx.d_write			= 1 ;
#endif
	int32_t	iRetVal = xNetOpen(&sServTNetCtx) ;			// default blocking state
	if (iRetVal >= erSUCCESS) {
		vRtosSetStatus(flagNET_TNET_SERV) ;
		memset(&sTerm, 0, sizeof(tnet_con_t)) ;
		TNetState = stateTELNET_WAITING ;
		IF_SL_DBG(debugTRACK, "waiting") ;
	}
}

/**
 * vTelnetTask()
 * @param pvParameters
 */
void	vTaskTelnet(void *pvParameters) {
	IF_TRACK(debugAPPL_THREADS, debugAPPL_MESS_UP) ;
	TNetState = stateTELNET_INIT ;
	while (xRtosVerifyState(taskTELNET)) {
		vRtosWaitStatus(flagNET_L3) ;
		switch(TNetState) {
		int32_t	iRetVal ;
		char cChr ;
		case stateTELNET_INIT:
			vTelnetInit() ;
			vTaskDelay(pdMS_TO_TICKS(telnetINTERVAL_MS)) ;
			break ;

		case stateTELNET_WAITING:
			iRetVal = xNetAccept(&sServTNetCtx, &sTerm.sCtx, telnetINTERVAL_MS) ;
			if (sServTNetCtx.error == EAGAIN || sServTNetCtx.error == ECONNABORTED) {
				break ;
			} else if (iRetVal < 0) {
				vTelnetDeInit() ;
				IF_SL_DBG(debugRESULT, TRACK_FORMAT, __LINE__,  iRetVal) ;
				break ;
			}

			// setup the client session timeout
			iRetVal = xNetSetRecvTimeOut(&sTerm.sCtx, telnetINTERVAL_MS) ;
			if (iRetVal != erSUCCESS) {
				vTelnetDeInit() ;
				IF_SL_DBG(debugRESULT, TRACK_FORMAT, __LINE__,  iRetVal) ;
				break ;
			}
			vRtosSetStatus(flagNET_TNET_CLNT) ;
			iRetVal = xTelnetFlushBuf() ;				// empty the Xmt buf if required..
			if (iRetVal > 0) {							// if no error, send default options
				iRetVal = xTelnetSendDefaultOptions() ;
			}
			if (iRetVal > 0) {
				TNetState = stateTELNET_OPTIONS ;		// and start processing options
				IF_SL_DBG(debugTRACK, "connected") ;
			} else {
				vTelnetDeInit() ;
				IF_SL_DBG(debugRESULT, TRACK_FORMAT, __LINE__,  iRetVal) ;
			}
			/* In order to ensure the remote terminal has sufficient time to prepare and
			 * send their options, we break here to resume the next state shortly */
			break ;

		case stateTELNET_OPTIONS:
			while (1) {
				iRetVal = xNetRead(&sTerm.sCtx, &cChr, sizeof(cChr)) ;
				if (iRetVal <= 0) {
					if (sTerm.sCtx.error != EAGAIN) {	// socket closed or error (excl EAGAIN)
						vTelnetCloseClient() ;
					} else {
#if		(configAUTHENTICATE == 1)
						TNetState = stateTELNET_AUTHEN ;	// no char, start authenticate
#else
						TNetState = stateTELNET_RUNNING ;	// no char, start running
#endif
					}
					break ;
				}
				xTelnetParseChar(cChr) ;
			}
			break ;

#if		(configAUTHENTICATE == 1)
		case stateTELNET_AUTHEN:
			if (xAuthenticate(sTerm.sCtx.sd, configUSERNAME, configPASSWORD, 1) == erSUCCESS) {
				TNetState = stateTELNET_RUNNING ;
			} else {
				if (errno != EAGAIN) {
					vTelnetCloseClient() ;
					IF_SL_DBG(debugRESULT, "@%d errno=%d '%s'", __LINE__, errno, strerror(errno)) ;
				}
				break ;
			}
#endif
			/* no break */

		case stateTELNET_RUNNING:
			iRetVal = xNetRead(&sTerm.sCtx, &cChr, sizeof(cChr)) ;
			if ((iRetVal < 0) && (sTerm.sCtx.error != EAGAIN)) {
				vTelnetCloseClient() ;			// socket closed or error (but not EAGAIN)
				break ;
			}
			xStdOutLock(portMAX_DELAY) ;
			if (iRetVal > 0) {
				vCommandInterpret(1, cChr) ;
			}
			if (sBufStdOut.Used) {
				iRetVal = xTelnetFlushBuf() ;		// empty the Xmt buf if required..
				if (iRetVal < 1) {
					vTelnetDeInit() ;
					IF_SL_DBG(debugRESULT, TRACK_FORMAT, __LINE__,  iRetVal) ;
				}
			}
			xStdOutUnLock() ;
			break ;

		case stateTELNET_CLOSE:
			vTelnetCloseClient() ;
			break ;
		default:
			myASSERT(0) ;
		}
	}
	IF_TRACK(debugAPPL_THREADS, debugAPPL_MESS_DN) ;
	xTelnetFlushBuf() ;
	vTelnetDeInit() ;
	vTaskDelete(NULL) ;
}

void	vTaskTelnetInit(void) { xRtosTaskCreate(vTaskTelnet, "TNET", telnetSTACK_SIZE, 0, telnetPRIORITY, NULL, INT_MAX) ; }

void	vTelnetReport(int32_t Handle) {
	if (xRtosCheckStatus(flagNET_TNET_CLNT)) {
		xNetReport(Handle, &sTerm.sCtx, __FUNCTION__, 0, 0, 0) ;
	}
	if (xRtosCheckStatus(flagNET_TNET_SERV)) {
		xNetReport(Handle, &sServTNetCtx, __FUNCTION__, 0, 0, 0) ;
		xdprintf(Handle, "\t\t\tState=%d  maxTX=%u  maxRX=%u\n", TNetState, sServTNetCtx.maxTx, sServTNetCtx.maxRx) ;
	}
}
#endif
