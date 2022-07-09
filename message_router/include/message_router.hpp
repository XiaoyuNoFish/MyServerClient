#ifndef __MESSAGE_ROUTER_HPP__
#define __MESSAGE_ROUTER_HPP__

#include <chrono>
#include <condition_variable>
#include <deque>
#include <fstream>
#include <iostream>
#include <mutex>
#include <queue>
#include <shared_mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <algorithm>
#include <errno.h>
#include <json/json.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "local_msg_type.hpp"

extern Json::Value json_config;

struct user_item {
    int socket_fd;
    SSL* ssl_fd;
    short int count_down;
    bool is_down = true;
};

struct message_item_t {
    std::string receiver{};
    std::string sender{};
    std::string type{};
    std::string content{};
    unsigned char tried_num = 0;
};

class Message_router {
private:
    char success_tag;
    //! meanings:
    //! 0: success
    //! -1: can't create epoll
    //! -2: can't open log file

    static bool if_continue_tag;
    static std::mutex if_continue_mtx;

    static SSL_CTX* ssl_ctx_fd;
    static std::condition_variable* local_msg_queue_cv;
    static std::mutex* local_msg_queue_mtx;
    static std::queue<struct local_msg_type_t>* local_msg_queue;

    static std::mutex log_file_mtx;
    static std::ofstream log_file;

    static std::mutex socket_mtx;
    static epoll_event* epoll_events_ptr;
    static int epoll_fd;
    //用户名到用户结构体的哈希表
    static std::unordered_map<std::string, struct user_item> user_map;
    static std::vector<std::string> all_users_index; //所有用户名
    static std::vector<std::string> user_index;
    //文件描述符到用户名的哈希表
    static std::unordered_map<int, std::string> user_rindex;

    static std::queue<struct message_item_t> message_queue;
    static std::unordered_map<std::string, std::vector<struct message_item_t>> to_be_sent_message_map;

    static time_t tmp_time_t;
    static std::chrono::system_clock::time_point tmp_now_time;

public:
    Message_router(SSL_CTX* tmp_ssl_ctx_fd, std::condition_variable* tmp_local_queue_cv, std::mutex* queue_mtx, std::queue<struct local_msg_type_t>* queue_ptr);
    ~Message_router();
    char get_success_tag(void);
    static void local_msg_listener();
    static void set_if_continue_flag(void);
    static void message_worker(void);
    static void message_consumer(void);
    static void cleaner(void);

private:
    static char* now_time(void);
};

#endif