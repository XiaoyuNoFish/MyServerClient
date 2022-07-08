#ifndef _LOCAL_MSG_TYPE_HPP_
#define _LOCAL_MSG_TYPE_HPP_

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <string>

#define LOCAL_MSG_TYPE_USER_LOGIN 1 //用户登录标志
#define LOCAL_MSG_TYPE_USER_LIST 2  //用户列表

struct local_msg_type_t {
    char type;
    std::string name;
    int socket_fd;
    SSL* ssl_fd;
};

#endif