// tnet_auth.c -Copyright (c) 2017-24 Andre M. Maree / KSS Technologies (Pty) Ltd.

#include "tnet_auth.h"
#include "printfx.h"
#include "stdioX.h"
#include "socketsX.h"
#include "errors_events.h"

// ############################### BUILD: debug configuration options ##############################

#define	debugFLAG					0xF000

#define	debugTIMING					(debugFLAG_GLOBAL & debugFLAG & 0x1000)
#define	debugTRACK					(debugFLAG_GLOBAL & debugFLAG & 0x2000)
#define	debugPARAM					(debugFLAG_GLOBAL & debugFLAG & 0x4000)
#define	debugRESULT					(debugFLAG_GLOBAL & debugFLAG & 0x8000)

// ######################################## Public functions #######################################

const char cBS[3] = { CHR_BS, CHR_SPACE, CHR_BS };

int	xReadString(int sd, char * pcBuf, size_t Size, bool bEcho) {
	u8_t Idx = 0, cChr;
	while (1) {
		int iRV = read(sd, &cChr, sizeof(cChr));
		if (iRV == 1) {
			if (cChr == CHR_CR) {						// end of input
				pcBuf[Idx] = 0;
				break;
			} else if (cChr == CHR_BS) {				// correct typo
				if (Idx > 0)
					--Idx;								// if anything in buffer, step back 1 char
				else
					cChr = CHR_BEL;						// else buffer empty, ring the bell..
			} else if (Idx < (Size-1)) {				// space left in buffer ?
				if (INRANGE(CHR_SPACE, cChr, CHR_TILDE))
					pcBuf[Idx++] = cChr;				// & valid char, store in buffer
				else
					cChr = 0;
			} else {									// buffer is full
				break;									// go test what you have...
			}
			if (bEcho && (cChr != 0)) {
				if (cChr == CHR_BS)
					write(sd, cBS, sizeof(cBS));
				else
					write(sd, &cChr, sizeof(cChr));
			}
		} else if ((iRV == erFAILURE) && (errno != EAGAIN)) {
			return erFAILURE;
		}
		vTaskDelay(50);
	}
	if (cChr == CHR_CR)
		write(sd, strNL, strlen(strNUL));
	return Idx;
}

int	xAutheticateObject(int sd, const char * pcPrompt, const char * pcKey, bool bEcho) {
	char Buf[35];
	if (pcPrompt)
		dprintfx(sd, pcPrompt);
	int iRV = xReadString(sd, Buf, sizeof(Buf), bEcho);
	if (iRV <= 0)
		return erFAILURE;
	if (strcmp((char *) Buf, pcKey) != 0)
		return erFAILURE;
	return erSUCCESS;
}

int	xAuthenticate(int sd, const char * pcUsername, const char * pcPassword, bool bEcho) {
	if (xAutheticateObject(sd, "User: ", pcUsername, 1) == erSUCCESS)
		return xAutheticateObject(sd, strNL "Pswd: ", pcPassword, bEcho);
	return erFAILURE;
}
