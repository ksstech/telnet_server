set(srcs "x_authenticate.c" "x_telnet_server.c" )
set(include_dirs "." )
#set(priv_include_dirs "." )
set(requires x_sockets buffers )
set(priv_requires rtos-support printf common irmacos syslog commands hal_esp32 statistics )
#set(priv_requires ${priv_requires} m90e26 )
idf_component_register( SRCS ${srcs}
						INCLUDE_DIRS ${include_dirs} 
#						PRIV_INCLUDE_DIRS ${priv_include_dirs} 
						REQUIRES ${requires} 
						PRIV_REQUIRES ${priv_requires}
						)
