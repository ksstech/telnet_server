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

int	xAutheticateObject(int sd, const char * pcPrompt, const char * pcKey, bool bEcho) {
	char Buf[35];
	if (pcPrompt) dprintfx(sd, pcPrompt);
	int iRV = xReadString(sd, Buf, sizeof(Buf), bEcho);
	if (iRV <= 0) return erFAILURE;
	if (strcmp((char *) Buf, pcKey) != 0) return erFAILURE;
	return erSUCCESS;
}

int	xAuthenticate(int sd, const char * pcUsername, const char * pcPassword, bool bEcho) {
	if (xAutheticateObject(sd, "User: ", pcUsername, 1) != erSUCCESS) return erFAILURE;
	return xAutheticateObject(sd, "Pswd: ", pcPassword, bEcho);
}
