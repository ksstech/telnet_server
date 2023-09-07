/*
 * tnet_auth.h
 */

#pragma	once

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// ##################################### MACRO definitions #########################################

#ifndef	configUSERNAME
	#define	configUSERNAME			"TestUser"
#endif

#ifndef	configPASSWORD
	#define	configPASSWORD			"TestPass"
#endif

// ###################################### BUILD : CONFIG definitions ###############################


// ############################## BUILD : FreeRTOS Task definitions ################################


// ################################### Public/global functions #####################################

int	xAuthenticate(int sd, const char * pcUsername, const char * pcPassword, bool bEcho);

#ifdef __cplusplus
}
#endif
