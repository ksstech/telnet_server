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

/**
 * @brief		read a string from file specified and verify against key string provided 
 * @param[in]	sd - file handle to read input from
 * @param[in]	pcPrompt - pointer to prompt to be displayed
 * @param[in]	pcKey - pointer to required/valid string
 * @param[in]	bHide - flag to specify password echoed as '*'
 * @return		erSUCCESS if both string correctly verified else erfAILURE
 */
int	xAutheticateObject(int sd, const char * pcPrompt, const char * pcKey, bool bHide);

/**
 * @brief		Authenticate access using UN & PW 
 * @param[in]	sd - file handle to read input from
 * @param[in]	pcUN - pointer to required/valid username
 * @param[in]	pcPW - pointer to required/valid password
 * @param[in]	bHide - flag to specify password echoed as '*'
 * @return		erSUCCESS if both UN & PW correct else erfAILURE
 */
int	xAuthenticate(int sd, const char * pcUN, const char * pcPW, bool bHide);

#ifdef __cplusplus
}
#endif
