// tnet_auth.h

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

int	xAutheticateObject(int sd, const char * pcPrompt, const char * pcKey, bool bHide);

#ifdef __cplusplus
}
#endif
