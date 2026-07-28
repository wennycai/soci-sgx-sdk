#include "soci/soci.hpp"
#include <atomic>
#include <csignal>
#include <chrono>
#include <iostream>
#include <thread>
static std::atomic<bool> stop{false}; static void quit(int){stop=true;}
int main(int argc,char**argv){try{std::string dir=argc>1?argv[1]:"runtime/off";soci::Runtime r(dir);std::signal(SIGINT,quit);std::signal(SIGTERM,quit);std::cout<<SOCI_SERVICE_ROLE<<" service healthy; mode="<<r.mode()<<"\n";while(!stop)std::this_thread::sleep_for(std::chrono::milliseconds(200));}catch(const std::exception&e){std::cerr<<e.what()<<"\n";return 1;}}
