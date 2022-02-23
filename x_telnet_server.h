/*
 * x_telnet_server.h
 */

#pragma once

#include	"hal_variables.h"
#include	"FreeRTOS_Support.h"

#include	"socketsX.h"
#include	"x_ubuf.h"

#ifdef __cplusplus
extern "C" {
#endif

// ########################################### Macros ##############################################

#define	tnetPRIORITY						3
#define	tnetSTACK_SIZE						(configMINIMAL_STACK_SIZE + 1024 + (flagSTACK * 256))
#define	tnetAUTHENTICATE					0

// ######################################### enumerations ##########################################

enum tnetCMD {
    tnetSE        		= 240,				// Subnegotiation End
    tnetNOP        		= 241,				// No OPeration
    tnetDM        		= 242,				// Data Mark
    tnetBRK        		= 243,				// NVT Character BReaK
    tnetIP        		= 244,				// Interrupt Process
    tnetAO        		= 245,				// Abort Output
    tnetAYT       		= 246,				// Are You There
    tnetEC        		= 247,				// Erase Character
    tnetEL        		= 248,				// Erase Line
    tnetGA        		= 249,				// Go Ahead
    tnetSB        		= 250,				// Subnegotiation Begin
    tnetWILL        	= 251,
    tnetWONT        	= 252,
    tnetDO        		= 253,
    tnetDONT        	= 254,
	tnetIAC				= 255,				// Interpret As Command
} ;

enum tnetOPT {
	tnetOPT_ECHO		= 1,				// https://tools.ietf.org/pdf/rfc857.pdf
	tnetOPT_SGA			= 3,				// https://tools.ietf.org/pdf/rfc858.pdf
	tnetOPT_TTYPE		= 24,
	tnetOPT_NAWS		= 31,
	tnetOPT_TSPEED		= 32,
	tnetOPT_LMODE		= 34,
	tnetOPT_OLD_ENV		= 36,
	tnetOPT_NEW_ENV		= 39,
	tnetOPT_STRT_TLS	= 46,
	tnetOPT_MAX_VAL,
	tnetOPT_UNDEF		= 255,
} ;

enum tnetOPT_VAL { valWILL, valWONT, valDO, valDONT } ;

enum tnetSTATE { tnetSTATE_DEINIT = 1, tnetSTATE_INIT, tnetSTATE_WAITING, tnetSTATE_OPTIONS, tnetSTATE_AUTHEN, tnetSTATE_RUNNING } ;

enum tnetSUBST { tnetSUBST_CHECK = 1, tnetSUBST_IAC, tnetSUBST_OPT, tnetSUBST_SB, tnetSUBST_OPTDAT, tnetSUBST_SE } ;

// ########################################## structures ###########################################


// ######################################## global variables #######################################


// ################################### GLOBAL Function Prototypes ##################################

void	vTnetTask(void *) ;
void	vTnetStartStop(void) ;
void	vTnetReport(void) ;

#ifdef __cplusplus
}
#endif
