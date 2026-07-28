#include "soci/soci.hpp"
#include <iostream>
int main(){soci::Runtime r("runtime/off");r.create_key("example");auto a=r.encrypt("20");auto b=r.encrypt("22");std::cout<<r.decrypt(r.add(a,b))<<"\n";}
