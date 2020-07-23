idf_component_register(
	SRCS "x_authenticate.c" "x_telnet_server.c"
	INCLUDE_DIRS "."
	PRIV_INCLUDE_DIRS
	REQUIRES
	PRIV_REQUIRES commands irmacos printf rtos-support
)
