/*
 * x_authenticate.c
 */

#include	"FreeRTOS_Support.h"

#include	"x_authenticate.h"
#include	"x_errors_events.h"
#include	"socketsX.h"
#include	"printfx.h"									// +x_definitions +stdarg +stdint +stdio

#include	<stdio.h>
#include	<string.h>

// ############################### BUILD: debug configuration options ##############################

#define	debugFLAG						0xC000

#define	debugTIMING					(debugFLAG_GLOBAL & debugFLAG & 0x1000)
#define	debugTRACK					(debugFLAG_GLOBAL & debugFLAG & 0x2000)
#define	debugPARAM					(debugFLAG_GLOBAL & debugFLAG & 0x4000)
#define	debugRESULT					(debugFLAG_GLOBAL & debugFLAG & 0x8000)

// ######################################## Public functions #######################################

char cBS[3] = { CHR_BS, CHR_SPACE, CHR_BS } ;

int32_t	xReadString(int sd, char * pcBuf, size_t Size, bool bEcho) {
	uint8_t	Idx = 0, cChr ;
	while (1) {
		int32_t iRV = read(sd, &cChr, sizeof(cChr)) ;
		if (iRV == sizeof(uint8_t)) {
			if (cChr == CHR_CR) {						// end of input
				pcBuf[Idx] = CHR_NUL ;
				break ;
			} else if (cChr == CHR_BS) {				// correct typo
				if (Idx > 0) {							// if anything in buffer
					--Idx ;								// step back 1 char
				} else {
					cChr = CHR_BEL ;					// else buffer empty, ring the bell..
				}
			} else if (Idx < (Size-1)) {				// space left in buffer ?
				if (INRANGE(CHR_SPACE, cChr, CHR_TILDE, int32_t)) {	// & valid char ?
					pcBuf[Idx++] = cChr ;				// store in buffer
				} else {
					cChr = CHR_NUL ;
				}
			} else {									// buffer is full
				break ;									// go test what you have...
			}
			if (bEcho && (cChr != CHR_NUL)) {
				if (cChr == CHR_BS) {
					write(sd, cBS, sizeof(cBS)) ;
				} else {
					write(sd, &cChr, sizeof(cChr)) ;
				}
			}
		} else if ((iRV == erFAILURE) && (errno != EAGAIN)) {
			return erFAILURE ;
		}
		vTaskDelay(50) ;
	}
	if (cChr == CHR_CR) {
		write(sd, "\r\n", 2) ;
	}
	return Idx ;
}

int32_t	xAutheticateObject(int sd, const char * pcPrompt, const char * pcKey, bool bEcho) {
	char Buf[35] ;
	if (pcPrompt) {
		dprintfx(sd, pcPrompt) ;
	}
	int32_t iRV = xReadString(sd, Buf, sizeof(Buf), bEcho) ;
	if (iRV <= 0) {
		return erFAILURE ;
	}
	if (strcmp((char *) Buf, pcKey) != 0) {
		return erFAILURE ;
	}
	return erSUCCESS ;
}

int32_t	xAuthenticate(int sd, const char * pcUsername, const char * pcPassword, bool bEcho) {
	if (xAutheticateObject(sd, "User: ", pcUsername, 1) == erSUCCESS) {
		return xAutheticateObject(sd, "Pswd: ", pcPassword, bEcho) ;
	}
	return erFAILURE ;
}
