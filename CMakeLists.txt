idf_component_register(
	SRCS "x_authenticate.c" "x_telnet_server.c"
	INCLUDE_DIRS "."
	PRIV_REQUIRES commands irmacos printfx rtos-support
)
