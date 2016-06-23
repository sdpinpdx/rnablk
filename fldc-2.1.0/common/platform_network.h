/*
 * Platform-specific network adaptations
 */

#ifndef _PLATFORM_NETWORK_H_
#define _PLATFORM_NETWORK_H_

#include "platform.h"

#ifdef WINDOWS_USER
# include <winsock2.h>
# include <ws2tcpip.h>

# pragma comment(lib, "Ws2_32.lib")
#elif defined(WINDOWS_KERNEL)

#include <wsk.h>

#elif defined(LINUX_USER)
# include <arpa/inet.h>
# include <netdb.h>
#elif defined(LINUX_KERNEL)
# include <linux/in.h>
#endif


#ifdef WINDOWS
typedef uint32_t    in_addr_t;
#endif  /* WINDOWS_USER */

#ifdef LINUX_KERNEL
typedef uint32_t    in_addr_t;
#endif  /* LINUX_KERNEL */

/**
 *  get_sockaddr_addr  --  Return addr from sockaddr_in
 */

INLINE struct in_addr
get_sockaddr_addr(const struct sockaddr_in *sa)
{
    return sa->sin_addr;
}


/**
 *  get_sockaddr_family  --  Return family from sockaddr_in
 */

INLINE short
get_sockaddr_family(const struct sockaddr_in *sa)
{
    return sa->sin_family;
}

#endif  /*  _PLATFORM_NETWORK_H_ */


/* vi: set sw=4 sts=4 tw=80: */
/* Emacs settings */
/* 
 * Local Variables:
 * c-basic-offset: 4
 * c-file-offsets: ((substatement-open . 0))
 * tab-width: 4
 * End:
 */
