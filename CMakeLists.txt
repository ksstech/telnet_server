# TELNET_SERVER

set( srcs "tnet_auth.c" "tnet_server.c" )
set( include_dirs "." )
set( priv_include_dirs )
set( requires "buffers socketsX" )
set( priv_requires "commands printfx syslog systiming" )

idf_component_register(
	SRCS ${srcs}
	INCLUDE_DIRS ${include_dirs}
	PRIV_INCLUDE_DIRS ${priv_include_dirs}
	REQUIRES ${requires}
	PRIV_REQUIRES ${priv_requires}
)
