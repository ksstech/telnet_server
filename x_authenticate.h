/*
 * x_authenticate.h
 */

#pragma	once

// ##################################### MACRO definitions #########################################


// ###################################### BUILD : CONFIG definitions ###############################


// ############################## BUILD : FreeRTOS Task definitions ################################


// ################################### Public/global functions #####################################

int32_t	xAuthenticate(int fd, char * pcUsername, char * pcPassword, bool bEcho) ;
