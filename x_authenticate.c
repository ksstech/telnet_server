/*
 * x_authenticate.c
 */

#include	"FreeRTOS_Support.h"
#include	"x_authenticate.h"
#include	"x_debug.h"
#include	"x_errors_events.h"

#include	<stdio.h>
#include	<string.h>

// ############################### BUILD: debug configuration options ##############################

#define	debugFLAG						0x0000
#define	debugPARAM						(debugFLAG & 0x0001)
#define	debugTRACK						(debugFLAG & 0x0002)

// ######################################## Public functions #######################################

char cBS[3] = { CHR_BS, CHR_SPACE, CHR_BS } ;

int32_t	xReadString(int fd, char * pcBuf, size_t Size, bool bEcho) {
	uint8_t	Idx = 0, cChr ;
	while (1) {
		int32_t iRV = read(fd, &cChr, sizeof(cChr)) ;
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
					write(fd, cBS, sizeof(cBS)) ;
				} else {
					write(fd, &cChr, sizeof(cChr)) ;
				}
			}
		} else if ((iRV == erFAILURE) && (errno != EAGAIN)) {
			return erFAILURE ;
		}
		vTaskDelay(50) ;
	}
	if (bEcho && (cChr == CHR_CR)) {
		write(fd, "\r\n", 2) ;
	}
	return Idx ;
}

int32_t	xAutheticateObject(int fd, const char * pcPrompt, const char * pcKey, bool bEcho) {
	char Buf[35] ;
	if (pcPrompt) {
		xdprintf(fd, pcPrompt) ;
	}
	int32_t iRV = xReadString(fd, Buf, sizeof(Buf), bEcho) ;
	if (iRV <= 0) {
		return erFAILURE ;
	}
	if (strcmp((char *) Buf, pcKey) != 0) {
		return erFAILURE ;
	}
	return erSUCCESS ;
}

int32_t	xAuthenticate(int fd, const char * pcUsername, const char * pcPassword, bool bEcho) {
	if (xAutheticateObject(fd, "UserID: ", pcUsername, 1) == erSUCCESS) {
		return xAutheticateObject(fd, "PssWrd: ", pcPassword, bEcho) ;
	}
	return erFAILURE ;
}
