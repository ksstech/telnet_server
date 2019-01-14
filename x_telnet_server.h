/*
 * x_telnet_server.h
 */

#pragma once

#include	"x_sockets.h"
#include	"x_ubuf.h"

#include	<stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ########################################### Macros ##############################################

#define	telnetPRIORITY					3
#define	telnetSTACK_SIZE				(configMINIMAL_STACK_SIZE + 1408 + (myDEBUG * 640))
#define	telnetMS_OPEN					1000
#define	telnetMS_ACCEPT					500
#define	telnetMS_OPTIONS				500
#define	telnetMS_READ_WRITE				70

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
    tnetSB        		= 250,				// SuBnegotiation
    tnetWILL        	= 251,
    tnetWONT        	= 252,
    tnetDO        		= 253,
    tnetDONT        	= 254,
	tnetIAC				= 255,				// Interpret As Command
} ;

enum tnetOPT {
	tnetOPT_ECHO		= 1,
	tnetOPT_SGA			= 3,
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

enum tnetSTATE {
	tnetSTATE_INIT,
	tnetSTATE_WAITING,
	tnetSTATE_OPTIONS,
	tnetSTATE_AUTHEN,
	tnetSTATE_RUNNING,
} ;

enum tnetSUBST {
	tnetSUBST_CHECK,
	tnetSUBST_IAC,
	tnetSUBST_OPT,
	tnetSUBST_SB,
	tnetSUBST_OPTDAT,
	tnetSUBST_SE,
} ;

// ########################################## structures ###########################################

typedef struct opts_s {
	uint8_t		val[10] ;
	const char *name[10] ;
} opts_t ;

typedef	struct tnet_state {
	sock_ctx_t	sCtx ;
	uint8_t		optdata[35] ;
	uint8_t		optlen ;
	uint8_t		code ;
	uint8_t		options[(tnetOPT_MAX_VAL+3)/4] ;
	union {												// internal flags
		struct {
			uint8_t	TxNow	: 1 ;
			uint8_t	Running	: 1 ;
		} ;
		uint8_t		flag ;
	} ;
} tnet_con_t ;

// ######################################## global variables #######################################


// ################################### GLOBAL Function Prototypes ##################################

void	vTelnetDeInit(void) ;

void	vTaskTelnet(void * pvParameters) ;
void	vTaskTelnetInit(void) ;
void	vTelnetReport(int32_t Handle) ;

#ifdef __cplusplus
}
#endif
