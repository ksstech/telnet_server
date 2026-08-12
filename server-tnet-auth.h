// tnet_auth.h

#pragma	once

#include "definitions.h"						// u32_t
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

/**
 * @brief		read a string from file specified and verify against key string provided 
 * @param[in]	sd - file handle to read input from
 * @param[in]	pcPrompt - pointer to prompt to be displayed
 * @param[in]	pcKey - pointer to required/valid string
 * @param[in]	bEcho - 0 = echo each character as '*', 1 = echo in clear
 * @param[in]	msTO - max time to wait for the input, 0 = wait forever
 * @return		erSUCCESS if both string correctly verified else erfAILURE
 */
int	xAutheticateObject(int sd, const char * pcPrompt, const char * pcKey, bool bEcho, u32_t msTO);

/**
 * @brief		Authenticate access using UN & PW 
 * @param[in]	sd - file handle to read input from
 * @param[in]	pcUN - pointer to required/valid username
 * @param[in]	pcPW - pointer to required/valid password
 * @param[in]	bEcho - 0 = echo the password as '*', 1 = echo in clear
 * @param[in]	msTO - max time to wait per prompt, 0 = wait forever
 * @return		erSUCCESS if both UN & PW correct else erfAILURE
 */
int	xAuthenticate(int sd, const char * pcUN, const char * pcPW, bool bEcho, u32_t msTO);

#ifdef __cplusplus
}
#endif
