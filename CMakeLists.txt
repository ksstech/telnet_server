# TELNET_SERVER

set( srcs "x_authenticate.c" "x_telnet_server.c" )
set( include_dirs "." )
set( priv_include_dirs )
set( requires buffers hal_esp32 rtos-support socketsX )
set( priv_requires commands common printfx syslog )

idf_component_register(
	SRCS ${srcs} 
	INCLUDE_DIRS ${include_dirs} 
	PRIV_INCLUDE_DIRS ${priv_include_dirs} 
	REQUIRES ${requires} 
	PRIV_REQUIRES ${priv_requires}
)
