// tnet_server.c - Copyright (c) 2017-24 Andre M. Maree / KSS Technologies (Pty) Ltd.

#include "hal_platform.h"
#include "hal_options.h"
#include "hal_rtc.h"

#include "certificates.h"
#include "commands.h"
#include "FreeRTOS_Support.h"
#include "hal_stdio.h"
#include "printfx.h"
#include "socketsX.h"
#include "syslog.h"
#include "tnet_auth.h"
#include "tnet_server.h"
#include "terminalX.h"
#include "errors_events.h"

#include <errno.h>

/* Documentation links
 * Obsolete:
 * 		https://tools.ietf.org/html/rfc698
 * Current:
 * 		https://tools.ietf.org/html/rfc854
 * 		https://tools.ietf.org/html/rfc5198
 */

// ############################### BUILD: debug configuration options ##############################

#define debugFLAG					0xF000
#define debugTIMING					(debugFLAG_GLOBAL & debugFLAG & 0x1000)
#define debugTRACK					(debugFLAG_GLOBAL & debugFLAG & 0x2000)
#define debugPARAM					(debugFLAG_GLOBAL & debugFLAG & 0x4000)
#define debugRESULT					(debugFLAG_GLOBAL & debugFLAG & 0x8000)

// ####################################### Macros ##################################################

#define tnetINTERVAL_MS 			100
#define tnetMS_CONNECT				100
#define tnetMS_READ_WRITE			70
#define tnetAUTHENTICATE			0

// ########################################## structures ###########################################

typedef struct opts_t { // used to decode known/supported options
	u8_t val[10];
	const char *name[10];
} opts_t;

typedef struct tnet_con_t {
	netx_t sCtx;
	u8_t optdata[35];
	u8_t optlen;
	u8_t code;
	u8_t options[(tnetOPT_MAX_VAL + 3) / 4];
	union { // internal flags
		struct __attribute__((packed)) {
			u8_t TxNow : 1;
			u8_t Running : 1;
			u8_t Spare : 6;
		};
		u8_t flag;
	};
	u16_t ColX, RowY;
} tnet_con_t;

// ##################################### Private/Static variables ##################################

const char *const codename[4] = {"WILL", "WONT", "DO", "DONT"};

opts_t options = {
	.val[0] = tnetOPT_ECHO,		.name[0] = "Echo",
	.val[1] = tnetOPT_SGA,		.name[1] = "SGA",
	.val[2] = tnetOPT_TTYPE,	.name[2] = "TType",
	.val[3] = tnetOPT_NAWS,		.name[3] = "NaWS",
	.val[4] = tnetOPT_TSPEED,	.name[4] = "TSPeed",
	.val[5] = tnetOPT_LMODE,	.name[5] = "LMode",
	.val[6] = tnetOPT_OLD_ENV,	.name[6] = "Oenv",
	.val[7] = tnetOPT_NEW_ENV,	.name[7] = "Nenv",
	.val[8] = tnetOPT_STRT_TLS,	.name[8] = "STLS",
	.val[9] = tnetOPT_UNDEF,	.name[9] = "Oxx",
};

// ####################################### Public Variables ########################################

TaskHandle_t TnetHandle;
StaticTask_t ttsTNET = {0};
StackType_t tsbTNET[tnetSTACK_SIZE] = {0};

static netx_t sServTNetCtx = {0};
static tnet_con_t sTerm = {0};
static u8_t State, SubState;

// ####################################### private functions #######################################

static void vTelnetUpdateStats(void) {
	if (sServTNetCtx.maxTx < sTerm.sCtx.maxTx)
		sServTNetCtx.maxTx = sTerm.sCtx.maxTx;
	if (sServTNetCtx.maxRx < sTerm.sCtx.maxRx)
		sServTNetCtx.maxRx = sTerm.sCtx.maxRx;
}

static void vTelnetDeInit(void) {
	if (sTerm.sCtx.sd > 0)
		xNetClose(&sTerm.sCtx);
	xRtosClearStatus(flagTNET_CLNT);
	sTerm.Running = 0;

	if (sServTNetCtx.sd > 0)
		xNetClose(&sServTNetCtx);
	xRtosClearStatus(flagTNET_SERV);
	State = tnetSTATE_INIT;
	IF_PX(debugTRACK && ioB1GET(ioTNETtrack), "[TNET] deinit" strNL);
}

static int xTelnetPutC(xp_t * psXP, int cChr) {
	u8_t u8Chr = cChr;
	int iRV = xNetSend(&sTerm.sCtx, &u8Chr, sizeof(u8Chr));
	return (iRV == sizeof(u8Chr)) ? cChr : iRV; 
}

static const char *xTelnetFindName(u8_t opt) {
	u8_t idx;
	for (idx = 0; options.val[idx] != tnetOPT_UNDEF; ++idx) {
		if (options.val[idx] == opt) break;
	}
	return options.name[idx];
}

/**
 * xTelnetSetOption() - store the value (WILL/WONT/DO/DONT) for a specific option.
 * @param option	ECHO ... START_TLS
 * @param code		WILL / WONT / DO / DONT
 */
static void xTelnetSetOption(u8_t opt, u8_t cmd) {
	IF_PX(debugTRACK && ioB1GET(ioTNETtrack), "o=%s(%d)  c=%d", xTelnetFindName(opt), opt, cmd);
	IF_myASSERT(debugPARAM, INRANGE(tnetWILL, cmd, tnetDONT));
	IF_myASSERT(debugPARAM, INRANGE(tnetOPT_ECHO, opt, tnetOPT_STRT_TLS));
	u8_t Xidx = opt / 4;	   // 2 bits/value, 4 options/byte
	u8_t Sidx = (opt % 4) * 2; // positions (0/2/4/6) to shift mask & value left
	sTerm.options[Xidx] &= 0x03 << Sidx;
	sTerm.options[Xidx] |= (cmd - tnetWILL) << Sidx;
	IF_PX(debugTRACK && ioB1GET(ioTNETtrack), " -> %s" strNL, codename[cmd - tnetWILL]);
}

/**
 * xTelnetGetOption() - retrieve the value (WILL/WONT/DO/DONT) for a specific option.
 * @param option	ECHO ... START_TLS
 * @return code		WILL / WONT / DO / DONT
 */
static u8_t xTelnetGetOption(u8_t opt) {
	IF_myASSERT(debugPARAM, INRANGE(tnetOPT_ECHO, opt, tnetOPT_STRT_TLS));
	u8_t val = (sTerm.options[opt / 4] >> ((opt % 4) * 2)) & 0x03;
	IF_PX(debugTRACK && ioB1GET(ioTNETtrack), "o=%s(%d)  v=%d" strNL, xTelnetFindName(opt), opt, val);
	return val;
}

static int xTelnetHandleSGA(void) {
	int iRV = xTelnetGetOption(tnetOPT_SGA);
	if (iRV == valDONT || iRV == valWONT) {
		u8_t cGA = tnetGA;
		iRV = xNetSend(&sTerm.sCtx, &cGA, sizeof(cGA));
		if (iRV != sizeof(cGA)) {
			vTelnetDeInit();
			return erFAILURE;
		}
	}
	return erSUCCESS;
}

/**
 * @brief	send a single option to the client
 * @param	opt - Option
 * @param	cmd - Value
 * @return	erSUCCESS or (-) error code or (+) number of bytes (very unlikely)
 */
static void vTelnetSendOption(u8_t opt, u8_t cmd) {
	u8_t cBuf[3] = {tnetIAC, cmd, opt};
	int iRV = xNetSend(&sTerm.sCtx, cBuf, sizeof(cBuf));
	if (iRV == sizeof(cBuf)) {
		xTelnetSetOption(opt, cmd);
		vTelnetUpdateStats();
	} else {
		vTelnetDeInit();
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
static void vTelnetNegotiate(u8_t opt, u8_t cmd) {
	IF_PX(debugTRACK && ioB1GET(ioTNETtrack), "o=%s(%d) = %s" strNL, xTelnetFindName(opt), opt, codename[cmd - tnetWILL]);
	switch (opt) {
	case tnetOPT_ECHO: {            // Client must not (DONT) and server WILL
		vTelnetSendOption(opt, (cmd == tnetWILL || cmd == tnetWONT) ? tnetDONT : tnetWILL);
		break;
    }
	case tnetOPT_SGA: {             // Client must (DO) and server WILL
		vTelnetSendOption(opt, (cmd == tnetWILL || cmd == tnetWONT) ? tnetDO : tnetWILL);
		break;
    }
	case tnetOPT_NAWS: {            // can have functionality
		vTelnetSendOption(opt, (cmd == tnetWILL || cmd == tnetWONT) ? tnetDO : tnetWILL);
		break;
    }
	default: // Client WILL/WONT, but Server DONT  <ALT>  Client DO/DONT but Server WONT
		vTelnetSendOption(opt, cmd == tnetWILL || cmd == tnetWONT ? tnetDONT : tnetWONT);
	}
}

static void vTelnetUpdateOption(void) {
	switch (sTerm.code) {
	case tnetOPT_NAWS:
		if (sTerm.optlen == 4) {
            sTerm.ColX = ntohs(*(unsigned short *)sTerm.optdata);
            sTerm.RowY = ntohs(*(unsigned short *)(sTerm.optdata + 2));
        	IF_PX(debugTRACK && ioB1GET(ioTNETtrack), "Applied NAWS  ColX=%d  RowY=%d" strNL, sTerm.ColX, sTerm.RowY);
		} else {
			SL_ERR("Ignored NAWS Len %d != 4", sTerm.optlen);
		}
		break;
	default:
		SL_ERR("Unsupported OPTION %d data (%d bytes)", sTerm.code, sTerm.optlen);
	}
}

static int xTelnetParseChar(int cChr) {
	switch (SubState) {
	case tnetSUBST_CHECK:
		if (cChr == tnetIAC) SubState = tnetSUBST_IAC;
		else if (cChr != tnetGA) return cChr; // RETURN the character
		break;
	case tnetSUBST_IAC:
		switch (cChr) {
		case tnetSB:
			SubState = tnetSUBST_SB;
			break;
		case tnetWILL:
		case tnetWONT:
		case tnetDO:
		case tnetDONT:
			sTerm.code = cChr; 
			SubState = tnetSUBST_OPT; 
			break;
		case tnetIAC:
			SubState = tnetSUBST_CHECK; 
			return cChr; // RETURN 2nd IAC
		default:
			SubState = tnetSUBST_CHECK;
		}
		break;
	case tnetSUBST_SB: // option ie NAWS, SPEED, TYPE etc
		sTerm.code = cChr;
		sTerm.optlen = 0;
		SubState = tnetSUBST_OPTDAT;
		break;
	case tnetSUBST_OPT:
		vTelnetNegotiate(cChr, sTerm.code);
		SubState = tnetSUBST_CHECK;
		break;
	case tnetSUBST_OPTDAT:
		if (cChr == tnetIAC) SubState = tnetSUBST_SE;
		else if (sTerm.optlen < sizeof(sTerm.optdata)) sTerm.optdata[sTerm.optlen++] = cChr;
		break;
	case tnetSUBST_SE:
		if (cChr == tnetSE) {
			vTelnetUpdateOption();
			SubState = tnetSUBST_CHECK;
			break;
		}
		/* FALLTHRU */ /* no break */
	default:
		IF_myASSERT(debugTRACK, 0);
	}
	return erSUCCESS;
}

static int xTelnetSetBaseline(void) {
	/*					Putty			MikroTik
	 *	WONT	DONT	no echo			local echo
	 *	WILL	DONT	no echo			no echo
	 */
	int iRV = xTelnetGetOption(tnetOPT_ECHO);
	if (iRV == valWILL || iRV == valDONT) {
		vTelnetSendOption(tnetOPT_ECHO, tnetDONT);
		vTelnetSendOption(tnetOPT_ECHO, tnetWILL);
	}
	/*					Putty			MikroTik
	 *	WONT	DONT	working			not working
	 *	WILL	DONT	not working		not working
	 *	WONT	DO		not working		not working
	 *	WILL	DO		not working		not working
	 */
	iRV = xTelnetGetOption(tnetOPT_SGA);
	if (iRV == valWONT || iRV == valDONT) {
		vTelnetSendOption(tnetOPT_SGA, tnetDO);
		vTelnetSendOption(tnetOPT_SGA, tnetWILL);
	}
	/*					Putty			MikroTik		Serial
	 *	WONT	DONT	
	 *	WILL	DONT	
	 *	WONT	DO		
	 *	WILL	DO		
	 */
	iRV = xTelnetGetOption(tnetOPT_NAWS);
	if (iRV == valWONT || iRV == valDONT) {
		vTelnetSendOption(tnetOPT_NAWS, tnetDO);
		vTelnetSendOption(tnetOPT_NAWS, tnetWILL);
	}
	return erSUCCESS;
}

/**
 * @brief	Write a block of data to the client device socket
 * @return	number of bytes written or 0 if error
 */
static int xTelnetWriteBlock(u8_t *pBuf, ssize_t Size) {
	int iRV = xNetSend(&sTerm.sCtx, pBuf, Size);
	if (iRV < 0)			SL_ERROR(iRV);
	else if (iRV != Size)	SL_WARN("Incomplete write %d != %d", Size, iRV);
	if (iRV > erFAILURE)	vTelnetUpdateStats();
	return iRV;
}

/**
 * @brief	send any/all buffered data to client
 * @return	0 (nothing to send), > 0 (bytes successfully sent) else < 0 (error code)
 */
static int xTelnetFlushBuf(void) {
	int iRV = xStdioEmptyBlock(xTelnetWriteBlock);
	if (iRV > erSUCCESS) xTelnetHandleSGA();
	if (iRV < erSUCCESS) State = tnetSTATE_DEINIT;
	return iRV;
}

/**
 * @brief	Main TelNet task
 */
static void vTnetTask(void *pvParameters) {
	vTaskSetThreadLocalStoragePointer(NULL, buildFRTLSP_EVT_MASK, (void *)taskTNET_MASK);
	int iRV = 0;
	u8_t caChr[2];
	State = tnetSTATE_INIT;
	xRtosSetTaskRUN(taskTNET_MASK);

	while (bRtosTaskWaitOK(taskTNET_MASK, portMAX_DELAY)) {
		if ((State != tnetSTATE_DEINIT) && xNetWaitLx(pdMS_TO_TICKS(tnetMS_CONNECT)) == 0) continue;
		switch (State) {
		case tnetSTATE_DEINIT: vTelnetDeInit(); break;	// must NOT fall through, IP Lx might have changed
		case tnetSTATE_INIT: {
			IF_PX(debugTRACK && ioB1GET(ioTNETtrack), "[TNET] init" strNL);
			memset(&sServTNetCtx, 0, sizeof(sServTNetCtx));
			sServTNetCtx.sa_in.sin_family = AF_INET;
			sServTNetCtx.sa_in.sin_port = htons(IP_PORT_TELNET);
			sServTNetCtx.type = SOCK_STREAM;
			sServTNetCtx.flags = SO_REUSEADDR;
			#if 0
			sServTNetCtx.d_open				= 1;
			sServTNetCtx.d_read				= 1;
			sServTNetCtx.d_write			= 1;
			sServTNetCtx.d_close			= 1;
			sServTNetCtx.d_accept			= 1;
			sServTNetCtx.d_select			= 1;
			#endif
			iRV = xNetOpen(&sServTNetCtx); 				// default blocking state
			if (iRV < erSUCCESS) {
				State = tnetSTATE_DEINIT;
				IF_PX(debugTRACK && ioB1GET(ioTNETtrack), "[TNET] open fail (%d" strNL, sServTNetCtx.error);
				vTaskDelay(pdMS_TO_TICKS(tnetINTERVAL_MS));
				break;
			}
			xRtosSetStatus(flagTNET_SERV);
			memset(&sTerm, 0, sizeof(tnet_con_t));
			State = tnetSTATE_WAITING;
			IF_PX(debugTRACK && ioB1GET(ioTNETtrack), "[TNET] waiting" strNL);
		}	/* FALLTHRU */ /* no break */
		case tnetSTATE_WAITING: {
			iRV = xNetAccept(&sServTNetCtx, &sTerm.sCtx, tnetINTERVAL_MS);
			if (iRV < erSUCCESS) {
				if ((sServTNetCtx.error != EAGAIN) && (sServTNetCtx.error != ECONNABORTED)) {
					State = tnetSTATE_DEINIT;
					IF_PX(debugTRACK && ioB1GET(ioTNETtrack), "[TNET] accept fail (%d)" strNL, sServTNetCtx.error);
				}
				break;
			}
			xRtosSetStatus(flagTNET_CLNT);

			iRV = xNetSetRecvTO(&sTerm.sCtx, tnetINTERVAL_MS);	// setup timeout for processing options
			if (iRV != erSUCCESS) {
				State = tnetSTATE_DEINIT;
				IF_PX(debugTRACK && ioB1GET(ioTNETtrack), "[TNET] rx timeout" strNL);
				break;
			}
			IF_PX(debugTRACK && ioB1GET(ioTNETtrack), "accept ok" strNL);
			State = tnetSTATE_OPTIONS; // and start processing options
			SubState = tnetSUBST_CHECK;
			sTerm.RowY = TERMINAL_DFLT_Y;
			sTerm.ColX = TERMINAL_DFLT_X;
			xTelnetSetBaseline();
			IF_PX(debugTRACK && ioB1GET(ioTNETtrack), "[TNET] baseline ok" strNL);
		}	/* FALLTHRU */ /* no break */
		case tnetSTATE_OPTIONS: {
			iRV = xNetRecv(&sTerm.sCtx, (u8_t *)caChr, 1);
			if (iRV != 1) {
				if (sTerm.sCtx.error != EAGAIN) { // socket closed or error (excl EAGAIN)
					iRV = sTerm.sCtx.error;
					State = tnetSTATE_DEINIT;
					break;
				}
				/* EAGAIN so unless completed OPTIONS phase (tnetSUBST_CHECK) try again */
				if (SubState != tnetSUBST_CHECK) break;
			} else {
				if (xTelnetParseChar(caChr[0]) == erSUCCESS) break;
				/* still in OPTIONS, read a character, was NOT parsed as a valid OPTION char, then HWHAP !!! */
				IF_myASSERT(debugTRACK && SubState != tnetSUBST_CHECK, 0);
			}
			// setup timeout for processing normal comms
			if ((iRV = xNetSetRecvTO(&sTerm.sCtx, tnetMS_READ_WRITE)) != erSUCCESS) {
				State = tnetSTATE_DEINIT;
				break;
			}
			State = tnetSTATE_AUTHEN; // no char, start authenticate
			SubState = tnetSUBST_CHECK;
			IF_PX(debugTRACK && ioB1GET(ioTNETtrack), "[TNET] options ok" strNL);
		}	/* FALLTHRU */ /* no break */
		case tnetSTATE_AUTHEN: {
			if (ioB1GET(ioTNETauth) && xAuthenticate(sTerm.sCtx.sd, configUSERNAME, configPASSWORD, ioB1GET(ioTNETEcho)) != erSUCCESS) {
				if (errno != EAGAIN) {
					State = tnetSTATE_DEINIT;
					IF_PX(debugTRACK && ioB1GET(ioTNETtrack), "[TNET] authen fail (%d)" strNL, sTerm.sCtx.error);
				}
				break;
			}
			IF_PX(debugTRACK && ioB1GET(ioTNETtrack), "[TNET] auth %s" strNL, ioB1GET(ioTNETauth) ? "PASS" : "Skip");
			// All options and authentication done, empty the buffer to the client
			#if (configCONSOLE_UART > (-1))
				xTelnetFlushBuf();
			#endif
			State = tnetSTATE_RUNNING;
		}	/* FALLTHRU */ /* no break */
		case tnetSTATE_RUNNING: {
			iRV = xNetRecv(&sTerm.sCtx, caChr, 1);		// Step 1: read a single character
			if (iRV != 1) {
				if (sTerm.sCtx.error != EAGAIN) {		// socket closed or error (but not EAGAIN)
					State = tnetSTATE_DEINIT;
					IF_PX(debugTRACK && ioB1GET(ioTNETtrack), "[TNET] read fail (%d)" strNL, sTerm.sCtx.error);
				} else {
				#if (configCONSOLE_UART > (-1))
					xTelnetFlushBuf();
				#endif
				}
				break;
			}
			// Step 2: check if not part of Telnet negotiation
			if (xTelnetParseChar(caChr[0]) == erSUCCESS) break;
			// Step 3: Ensure UARTx marked inactive
			#if (configCONSOLE_UART > (-1))
				clrSYSFLAGS(sfUXACTIVE);
			#endif
			// Step 4: Handle special (non-Telnet) characters
			if (caChr[0] == CHR_GS) { // cntl + ']'
				State = tnetSTATE_DEINIT;
				break;
			}
			// Step 5: must be a normal command character, process as if from UART console....
			command_t sCmd = { .pCmd=&caChr[0], .sRprt.putc=xTelnetPutC, .sRprt.fEcho=1, .sRprt.fNoLock=1, .sRprt.uSGR=sgrANSI };
			vTermPushMaxRowYColX();											// push/save current MaxXY values (UART)
			vTermSetMaxRowYColX(sTerm.RowY, sTerm.ColX);					// set new MaxXY values (Telnet)
			xCommandProcess(&sCmd);
			vTermPullMaxRowYColX();											// pull/restore original MaxXY values (UART)
			break;
		}
		default: IF_myASSERT(debugTRACK, 0);
		}
	}
	vTelnetDeInit();
	vTaskDelete(NULL);
}

void vTnetStartStop(void) {
	if (ioB1GET(ioTNETstart)) {
		xRtosClearTaskRUN(taskTNET_MASK);
		xRtosClearTaskDELETE(taskTNET_MASK);
		TnetHandle = xTaskCreateStaticPinnedToCore(vTnetTask, "tnet", tnetSTACK_SIZE, NULL, tnetPRIORITY, tsbTNET, &ttsTNET, tskNO_AFFINITY);
	} else {
		vTaskSetTerminateFlags(taskTNET_MASK);
	}
}

void vTnetReport(report_t *psR) {
	if (xRtosCheckStatus(flagTNET_SERV)) {
		xNetReport(psR, &sServTNetCtx, "TNsrv", 0, 0, 0);
		wprintfx(psR, "\tFSM=%d  [maxTX=%u  maxRX=%u] [MaxX=%hu  MaxY=%hu]" strNL, State,
						sServTNetCtx.maxTx, sServTNetCtx.maxRx, sTerm.ColX, sTerm.RowY);
	}
	if (xRtosCheckStatus(flagTNET_CLNT)) {
		xNetReport(psR, &sTerm.sCtx, "TNclt", 0, 0, 0);
		if (debugTRACK && ioB1GET(ioTNETtrack)) {
			wprintfx(psR, "%CTNopt%C\t", xpfCOL(colourFG_CYAN,0), xpfCOL(attrRESET,0));
			for (int idx = tnetOPT_ECHO; idx < tnetOPT_MAX_VAL; ++idx) {
				if (idx == 17 || idx == 33) wprintfx(psR, strNL "\t");
				wprintfx(psR, "%d/%s=%s ", idx, xTelnetFindName(idx), codename[xTelnetGetOption(idx)]);
			}
			wprintfx(psR, strNL);
		}
	}
}
