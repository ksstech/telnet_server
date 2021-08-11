/*
 * x_authenticate.h
 */

#pragma	once

// ##################################### MACRO definitions #########################################


// ###################################### BUILD : CONFIG definitions ###############################


// ############################## BUILD : FreeRTOS Task definitions ################################


// ################################### Public/global functions #####################################

int	xAuthenticate(int sd, const char * pcUsername, const char * pcPassword, bool bEcho) ;
