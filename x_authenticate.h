/*
 * x_authenticate.h
 */

#pragma	once

// ##################################### MACRO definitions #########################################


// ###################################### BUILD : CONFIG definitions ###############################


// ############################## BUILD : FreeRTOS Task definitions ################################


// ################################### Public/global functions #####################################

int32_t	xAuthenticate(int fd, const char * pcUsername, const char * pcPassword, bool bEcho) ;
