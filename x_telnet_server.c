/*
 * x_telnet_server.c - Telnet protocol support
 */

#include "hal_variables.h"			// required by options.h

#include "commands.h"
#include "FreeRTOS_Support.h"
#include "hal_stdio.h"
#include "printfx.h"									// +x_definitions +stdarg +stdint +stdio
#include "syslog.h"
#include "x_authenticate.h"
#include "x_telnet_server.h"
#include "x_terminal.h"
#include "x_errors_events.h"

#include <unistd.h>
#include <errno.h>

/* Documentation links
 * Obsolete:
 * 		https://tools.ietf.org/html/rfc698
 * Current:
 * 		https://tools.ietf.org/html/rfc854
 * 		https://tools.ietf.org/html/rfc5198
 */

// ############################### BUILD: debug configuration options ##############################

#define	debugFLAG					0xF000

#define	debugTIMING					(debugFLAG_GLOBAL & debugFLAG & 0x1000)
#define	debugTRACK					(debugFLAG_GLOBAL & debugFLAG & 0x2000)
#define	debugPARAM					(debugFLAG_GLOBAL & debugFLAG & 0x4000)
#define	debugRESULT					(debugFLAG_GLOBAL & debugFLAG & 0x8000)

// ####################################### Macros ##################################################

#define	tnetSTACK_SIZE				(configMINIMAL_STACK_SIZE + 2048 + (flagSTACK * 256))

#define	tnetMS_SOCKET				500
#define	tnetMS_READ_WRITE			70

#define	tnetAUTHENTICATE			0

// ########################################## structures ###########################################

typedef struct opts_t {									// used to decode known/supported options
	u8_t		val[10];
	const char *name[10];
} opts_t;

typedef	struct tnet_con_t {
	netx_t	sCtx;
	u8_t	optdata[35];
	u8_t	optlen;
	u8_t	code;
	u8_t	options[(tnetOPT_MAX_VAL+3)/4];
	union {												// internal flags
		struct __attribute__((packed)) {
			u8_t	TxNow	: 1;
			u8_t	Running	: 1;
			u8_t	Spare	: 6;
		};
		u8_t		flag;
	};
} tnet_con_t;

// ##################################### Private/Static variables ##################################

const char * const codename[4] = {"WILL", "WONT", "DO", "DONT"};

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
};

// ####################################### Public Variables ########################################

StaticTask_t ttsTNET = { 0 };
StackType_t tsbTNET[tnetSTACK_SIZE] = { 0 };

static netx_t	sServTNetCtx = { 0 };
static tnet_con_t	sTerm = { 0 };
static u8_t		TNetState;
static u8_t		TNetSubSt;

// ####################################### private functions #######################################

static void vTelnetDeInit(void) {
	if (sTerm.sCtx.sd > 0) {
		xNetClose(&sTerm.sCtx);
	}
	xRtosClearStatus(flagTNET_CLNT);
	sTerm.Running = 0;

	if (sServTNetCtx.sd > 0) {
		xNetClose(&sServTNetCtx);
	}
	xRtosClearStatus(flagTNET_SERV);
	TNetState = tnetSTATE_INIT;
	IF_RP(debugTRACK && ioB1GET(ioTNETtrack), "deinit\r\n");
}

static const char * xTelnetFindName(u8_t opt) {
	u8_t idx;
	for (idx = 0; options.val[idx] != tnetOPT_UNDEF; ++idx) {
		if (options.val[idx] == opt) {
			break;
		}
	}
	return options.name[idx];
}

/**
 * xTelnetSetOption() - store the value (WILL/WONT/DO/DONT) for a specific option.
 * @param option	ECHO ... START_TLS
 * @param code		WILL / WONT / DO / DONT
 */
static void xTelnetSetOption(u8_t opt, u8_t cmd) {
	IF_P(debugTRACK && ioB1GET(ioTNETtrack), "o=%d  c=%d", opt, cmd);
	IF_myASSERT(debugPARAM, INRANGE(tnetWILL, cmd, tnetDONT));
	IF_myASSERT(debugPARAM, INRANGE(tnetOPT_ECHO, opt, tnetOPT_STRT_TLS));
	u8_t	Xidx = opt / 4;							// 2 bits/value, 4 options/byte
	u8_t	Sidx = (opt % 4) * 2;						// positions (0/2/4/6) to shift mask & value left
	sTerm.options[Xidx]	&=  0x03 << Sidx;
	sTerm.options[Xidx]	|= (cmd - tnetWILL) << Sidx;
	IF_PL(debugTRACK && ioB1GET(ioTNETtrack), " -> %s\r\n", codename[cmd - tnetWILL]);
}

/**
 * xTelnetGetOption() - retrieve the value (WILL/WONT/DO/DONT) for a specific option.
 * @param option	ECHO ... START_TLS
 * @return code		WILL / WONT / DO / DONT
 */
static u8_t xTelnetGetOption(u8_t opt) {
	IF_myASSERT(debugPARAM, INRANGE(tnetOPT_ECHO, opt, tnetOPT_STRT_TLS));
	u8_t val = (sTerm.options[opt/4] >> ((opt % 4) * 2)) & 0x03;
	IF_PL(debugTRACK && ioB1GET(ioTNETtrack), "o=%d  v=%d\r\n", opt, val);
	return val;
}

static void vTelnetUpdateStats(void) {
	if (sServTNetCtx.maxTx < sTerm.sCtx.maxTx) {
		sServTNetCtx.maxTx = sTerm.sCtx.maxTx;
	}
	if (sServTNetCtx.maxRx < sTerm.sCtx.maxRx) {
		sServTNetCtx.maxRx = sTerm.sCtx.maxRx;
	}
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
 * xTelnetSendOptions() - send a single option to the client
 * @param o1	Option
 * @param o2	Value
 * @return		erSUCCESS or (-) error code or (+) number of bytes (very unlikely)
 */
static void vTelnetSendOption(u8_t opt, u8_t cmd) {
	u8_t cBuf[3] = { tnetIAC, cmd, opt };
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
	IF_PL(debugTRACK && ioB1GET(ioTNETtrack), "%02d/%s = %s\r\n", opt, xTelnetFindName(opt), codename[cmd-tnetWILL]);
	switch (opt) {
	case tnetOPT_ECHO:				// Client must not (DONT) and server WILL
		vTelnetSendOption(opt, (cmd == tnetWILL || cmd == tnetWONT) ? tnetDONT : tnetWILL);
		break;

	case tnetOPT_SGA:				// Client must (DO) and server WILL
		vTelnetSendOption(opt, (cmd == tnetWILL || cmd == tnetWONT) ? tnetDO : tnetWILL);
		break;

	#if (buildTERMINAL_CONTROLS_CURSOR == 1)
	case tnetOPT_NAWS:				// can have functionality
//AMM	vTelnetSendOption(opt, cmd==tnetWILL ? tnetDO : cmd==tnetWONT ? tnetDONT : cmd==tnetDO ? tnetWILL : tnetWONT);
		vTelnetSendOption(opt, (cmd == tnetWILL || cmd == tnetWONT) ? tnetDO : tnetWILL);
		break;
	#endif

	default:		// Client WILL/WONT, but Server DONT  <ALT>  Client DO/DONT but Server WONT
		vTelnetSendOption(opt, cmd==tnetWILL || cmd==tnetWONT ? tnetDONT : tnetWONT);
	}
}

static void vTelnetUpdateOption(void) {
	switch (sTerm.code) {
	case tnetOPT_NAWS:
		if (sTerm.optlen == 4) {
	#if	(buildTERMINAL_CONTROLS_CURSOR == 1)		// NOT TESTED, check against RFC
			vTerminalSetSize(ntohs(*(unsigned short *) sTerm.optdata), ntohs(*(unsigned short *) (sTerm.optdata + 2)));
			SL_INFO("Applied NAWS C=%d R=%d", ntohs(*(unsigned short *) sTerm.optdata), ntohs(*(unsigned short *) (sTerm.optdata + 2)));
	#else
			SL_NOT("Ignored NAWS C=%d R=%d", ntohs(*(unsigned short *) sTerm.optdata), ntohs(*(unsigned short *) (sTerm.optdata + 2)));
	#endif
		} else {
			SL_ERR("Ignored NAWS Len %d != 4", sTerm.optlen );
		}
		break;
	default:
		SL_ERR("Unsupported OPTION %d data (%d bytes)", sTerm.code, sTerm.optlen);
	}
}

static int xTelnetParseChar(int cChr) {
	switch (TNetSubSt) {
	case tnetSUBST_CHECK:
		if (cChr == tnetIAC) {
			TNetSubSt = tnetSUBST_IAC;
		} else if (cChr != tnetGA) {
			return cChr;								// RETURN the character
		}
		break;
	case tnetSUBST_IAC:
		switch (cChr) {
		case tnetSB:
			TNetSubSt = tnetSUBST_SB;
			break;
		case tnetWILL:
		case tnetWONT:
		case tnetDO:
		case tnetDONT:
			sTerm.code = cChr;
			TNetSubSt = tnetSUBST_OPT;
			break;
		case tnetIAC:
			TNetSubSt = tnetSUBST_CHECK;
			return cChr;								// RETURN 2nd IAC
		default:
			TNetSubSt = tnetSUBST_CHECK;
		}
		break;
	case tnetSUBST_SB:									// option ie NAWS, SPEED, TYPE etc
		sTerm.code	= cChr;
		sTerm.optlen = 0;
		TNetSubSt = tnetSUBST_OPTDAT;
		break;
	case tnetSUBST_OPT:
		vTelnetNegotiate(cChr, sTerm.code);
		TNetSubSt = tnetSUBST_CHECK;
		break;
	case tnetSUBST_OPTDAT:
		if (cChr == tnetIAC) {
			TNetSubSt = tnetSUBST_SE;
		} else if (sTerm.optlen < sizeof(sTerm.optdata)) {
			sTerm.optdata[sTerm.optlen++] = cChr;
		}
		break;
	case tnetSUBST_SE:
		if (cChr == tnetSE) {
			vTelnetUpdateOption();
			TNetSubSt = tnetSUBST_CHECK;
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
	return erSUCCESS;
}

/**
 * @brief	Write a block of data to the client device socket
 * @return	number of bytes written or 0 if error
 */
int xTelnetWriteBlock(u8_t * pBuf, ssize_t Size) {
	int iRV = xNetSend(&sTerm.sCtx, pBuf, Size);
	if (iRV < 0) {
		xSyslogError(__FUNCTION__, iRV);
		iRV = 0;
	} else if (iRV != Size) {
		SL_WARN("Incomplete write %d != %d", Size, iRV);
	}
	vUBufStepRead(&sRTCvars.sRTCbuf, iRV);
	vTelnetUpdateStats();
	return iRV;
}

/**
 * @brief	send any/all buffered data to client
 * @return	non-zero positive value if nothing to send or all successfully sent
 *			0 (if socket closed) or other negative error code
 */
int xTelnetFlushBuf(void * pV, const char * pCC, va_list vaList) {
	int iRV = xStdioEmptyBlock(xTelnetWriteBlock);
	if (iRV > 0)
		xTelnetHandleSGA();
	if (iRV < erSUCCESS)
		TNetState = tnetSTATE_DEINIT;
	return (iRV < erSUCCESS) ? iRV : erSUCCESS;
}

/**
 * @brief	Main TelNet task
 */
static void vTnetTask(void *pvParameters) {
	vTaskSetThreadLocalStoragePointer(NULL, buildFRTLSP_EVT_MASK, (void *)taskTNET_MASK);
	int	iRV = 0;
	u8_t caChr[2];
	TNetState = tnetSTATE_INIT;
	xRtosSetStateRUN(taskTNET_MASK);

	while (bRtosVerifyState(taskTNET_MASK)) {
		if (TNetState != tnetSTATE_DEINIT) {
			EventBits_t CurStat = xNetWaitLx(flagLX_ANY, pdMS_TO_TICKS(tnetMS_SOCKET));
			if ((CurStat & flagL3_STA) != flagL3_STA &&
				(CurStat & flagLX_SAP) != flagLX_SAP) {
				continue;
			}
		}
		switch(TNetState) {
		case tnetSTATE_DEINIT:
			vTelnetDeInit();		// must NOT fall through, IP Lx might have changed
			break;

		case tnetSTATE_INIT:
			IF_RP(debugTRACK && ioB1GET(ioTNETtrack), "init\r\n");
			memset(&sServTNetCtx, 0 , sizeof(sServTNetCtx));
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
			iRV = xNetOpen(&sServTNetCtx);			// default blocking state
			if (iRV < erSUCCESS) {
				TNetState = tnetSTATE_DEINIT;
				IF_RP(debugTRACK && ioB1GET(ioTNETtrack), "open fail (%d\r\n", sServTNetCtx.error);
				vTaskDelay(pdMS_TO_TICKS(tnetMS_SOCKET));
				break;
			}
			xRtosSetStatus(flagTNET_SERV);
			memset(&sTerm, 0, sizeof(tnet_con_t));
			TNetState = tnetSTATE_WAITING;
			IF_RP(debugTRACK && ioB1GET(ioTNETtrack), "waiting\r\n");
			/* FALLTHRU */ /* no break */

		case tnetSTATE_WAITING:
			iRV = xNetAccept(&sServTNetCtx, &sTerm.sCtx, pdMS_TO_TICKS(tnetMS_SOCKET));
			if (iRV < erSUCCESS) {
				if ((sServTNetCtx.error != EAGAIN) && (sServTNetCtx.error != ECONNABORTED)) {
					TNetState = tnetSTATE_DEINIT;
					IF_RP(debugTRACK && ioB1GET(ioTNETtrack), "accept fail (%d)\r\n", sServTNetCtx.error);
				}
				break;
			}
			xRtosSetStatus(flagTNET_CLNT);

			// setup timeout for processing options
			iRV = xNetSetRecvTO(&sTerm.sCtx, tnetMS_SOCKET);
			if (iRV != erSUCCESS) {
				TNetState = tnetSTATE_DEINIT;
				IF_RP(debugTRACK && ioB1GET(ioTNETtrack), "rx timeout\r\n");
				break;
			}
			IF_RP(debugTRACK && ioB1GET(ioTNETtrack), "accept ok\r\n");
			TNetState = tnetSTATE_OPTIONS;			// and start processing options
			TNetSubSt = tnetSUBST_CHECK;
			xTelnetSetBaseline();
			IF_RP(debugTRACK && ioB1GET(ioTNETtrack), "baseline ok\r\n");
			/* FALLTHRU */ /* no break */

		case tnetSTATE_OPTIONS:
			iRV = xNetRecv(&sTerm.sCtx, (u8_t *) caChr, 1);
			if (iRV != 1) {
				if (sTerm.sCtx.error != EAGAIN) {	// socket closed or error (excl EAGAIN)
					iRV = sTerm.sCtx.error;
					TNetState = tnetSTATE_DEINIT;
					break;
				}
				/* EAGAIN so unless completed OPTIONS phase (tnetSUBST_CHECK) try again */
				if (TNetSubSt != tnetSUBST_CHECK) {
					break;
				}
			} else {
				if (xTelnetParseChar(caChr[0]) == erSUCCESS) {
					break;
				}
				/* still in OPTIONS, read a character, was NOT parsed as a valid OPTION char, then HWHAP !!! */
				IF_myASSERT(debugTRACK && TNetSubSt != tnetSUBST_CHECK, 0);
			}
			// setup timeout for processing normal comms
			if ((iRV = xNetSetRecvTO(&sTerm.sCtx, tnetMS_READ_WRITE)) != erSUCCESS) {
				TNetState = tnetSTATE_DEINIT;
				break;
			}
			TNetState = tnetSTATE_AUTHEN;				// no char, start authenticate
			TNetSubSt = tnetSUBST_CHECK;
			IF_RP(debugTRACK && ioB1GET(ioTNETtrack), "options ok\r\n");
			/* FALLTHRU */ /* no break */

		case tnetSTATE_AUTHEN:
			if (ioB1GET(ioTNETauth) && xAuthenticate(sTerm.sCtx.sd, configUSERNAME, configPASSWORD, true) != erSUCCESS) {
				if (errno != EAGAIN) {
					TNetState = tnetSTATE_DEINIT;
					IF_RP(debugTRACK && ioB1GET(ioTNETtrack), "authen fail (%d)\r\n", sTerm.sCtx.error);
				}
				break;
			}
			IF_RP(debugTRACK && ioB1GET(ioTNETtrack), "auth ok\r\n");
			// All options and authentication done, empty the buffer to the client
			xCommandProcessString("\0", 0, xTelnetFlushBuf, NULL, NULL);
			TNetState = tnetSTATE_RUNNING;
			/* FALLTHRU */ /* no break */

		case tnetSTATE_RUNNING:
			// Step 1: read a single character
			iRV = xNetRecv(&sTerm.sCtx, caChr, 1);
			if (iRV != 1) {
				if (sTerm.sCtx.error != EAGAIN) {		// socket closed or error (but not EAGAIN)
					TNetState = tnetSTATE_DEINIT;
					IF_RP(debugTRACK && ioB1GET(ioTNETtrack), "read fail (%d)\r\n", sTerm.sCtx.error);
				} else {
					xCommandProcessString("\0", 0, xTelnetFlushBuf, NULL, NULL);
				}
				break;
			}
			// Step 2: check if not part of Telnet negotiation
			if (xTelnetParseChar(caChr[0]) == erSUCCESS) {
				break;
			}
			// Step 3: Ensure UARTx marked inactive
			clrSYSFLAGS(sfU0ACTIVE << configSTDIO_UART_CHAN);
			// Step 4: Handle special (non-Telnet) characters
			if (caChr[0] == CHR_GS) {						// cntl + ']'
				TNetState = tnetSTATE_DEINIT;
				break;
			}
			// Step 4: must be a normal command character, process as if from UART console....
			caChr[1] = 0;
			xCommandProcessString((char *) caChr, 1, xTelnetFlushBuf, NULL, NULL);
			break;

		default: IF_myASSERT(debugTRACK, 0);
		}
	}
	vTelnetDeInit();
	vRtosTaskDelete(NULL);
}

void vTnetStartStop(void) {
	if (ioB1GET(ioTNETstart)) {
		xRtosClearStateRUN(taskTNET_MASK);
		xRtosClearStateDELETE(taskTNET_MASK);
		xRtosTaskCreateStatic(vTnetTask, "tnet", tnetSTACK_SIZE, NULL, 3, tsbTNET, &ttsTNET, tskNO_AFFINITY);
	} else {
		vRtosTaskTerminate(taskTNET_MASK);
	}
}

void vTnetReport(void) {
	if (bRtosCheckStatus(flagTNET_SERV) == 1) {
		xNetReport(&sServTNetCtx, "TNETsrv", 0, 0, 0);
		P("\tFSM=%d  maxTX=%u  maxRX=%u\r\n", TNetState, sServTNetCtx.maxTx, sServTNetCtx.maxRx);
	}
	if (bRtosCheckStatus(flagTNET_CLNT) == 1) {
		xNetReport(&sTerm.sCtx, "TNETclt", 0, 0, 0);
		#if	(debugTRACK)
		if (ioB1GET(ioTNETtrack)) {
			P("%CTNETxxx%C\t", colourFG_CYAN, attrRESET);
			for (int idx = tnetOPT_ECHO; idx < tnetOPT_MAX_VAL; ++idx) {
				if (idx == 17 || idx == 33) {
					P("\r\n\t");
				}
				P("%d/%s=%s ", idx, xTelnetFindName(idx), codename[xTelnetGetOption(idx)]);
			}
			P(strCRLF);
		}
		#endif
		#if	(buildTERMINAL_CONTROLS_CURSOR == 1)
		terminfo_t TermInfo;
		vTerminalGetInfo(&TermInfo);
		P("%CTNETwin%C\tCx=%d  Cy=%d  Mx=%d  My=%d\r\n", colourFG_CYAN,
			attrRESET, TermInfo.CurX, TermInfo.CurY, TermInfo.MaxX, TermInfo.MaxY);
		#endif
	}
}
