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
#define	telnetSTACK_SIZE				(configMINIMAL_STACK_SIZE + 1536)
#define telnetINTERVAL_MS				200

// ####################################### Telnet COMMAND codes ####################################

#define	telnetIAC						255				// Interpret As Command
#define	telnetDONT						254
#define	telnetDO						253
#define	telnetWONT						252
#define	telnetWILL						251
#define	telnetSB						250				// SuBnegotiation
#define	telnetGA						249				// Go Ahead
#define	telnetEL						248				// Erase Line
#define	telnetEC						247				// Erase Character
#define	telnetAYT						246				// Are You There
#define	telnetAO						245				// Abort Output
#define	telnetIP						244				// Interrupt Process
#define	telnetBRK						243				// NVT Character BReaK
#define	telnetDM						242				// Data Mark
#define	telnetNOP						241				// No OPeration
#define	telnetSE						240				// Subnegotiation End

// ####################################### Telnet OPTION codes #####################################

#define	telnetOPT_ECHO					1				// ECHO
#define	telnetOPT_SUP_GOAHEAD			3				// Suppress Go Ahead

#define	telnetOPT_TERM_TYPE				24				// Terminal Type
#define	telnetOPT_NAWS					31				// Negotiate About Window Size
#define	telnetOPT_TERM_SPD				32				// Terminal Speed
#define	telnetOPT_LINEMODE				34				// Support client side line editing
#define	telnetOPT_OLD_ENVIRON			36				// Old Environment
#define	telnetOPT_NEW_ENVIRON			39				// New Environment
#define	telnetOPT_START_TLS				46

// ######################################### enumerations ##########################################

enum {
	stateTELNET_INIT,
	stateTELNET_WAITING,
	stateTELNET_OPTIONS,
	stateTELNET_IAC,
	stateTELNET_OPT,
	stateTELNET_SB,
	stateTELNET_OPTDAT,
	stateTELNET_SE,
	stateTELNET_MAX,
	stateTELNET_AUTHEN,
	stateTELNET_RUNNING,
	stateTELNET_CLOSE,
} ;

// ########################################## structures ###########################################

typedef	struct tnet_state {
	sock_ctx_t	sCtx ;
	uint8_t		optdata[35] ;
	uint8_t		code ;
	uint8_t		optlen ;
	union {
		struct {
			uint8_t	TxNow	: 1 ;
			uint8_t	SupGA	: 1 ;
		} ;
		uint8_t		flag ;
	};
} tnet_con_t ;

extern uint8_t	TNetState ;

// ######################################## global variables #######################################


// ################################### GLOBAL Function Prototypes ##################################

void	vTelnetInit(void) ;
void	vTelnetDeInit(void) ;

void	vTaskTelnet(void * pvParameters) ;
void	vTaskTelnetInit(void) ;
void	vTelnetReport(int32_t Handle) ;

#ifdef __cplusplus
}
#endif
