idf_component_register(SRCS x_authenticate.c x_telnet_server.c 
							INCLUDE_DIRS . 
							REQUIRES x_sockets buffers
							PRIV_REQUIRES rtos-support printf common x_sockets irmacos syslog commands hal_esp32 statistics
							)
target_compile_options( ${COMPONENT_LIB} PRIVATE -Wimplicit-fallthrough=0 )
