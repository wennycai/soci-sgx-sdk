#include <sgx_urts.h>
#include "soci_u.h"
#include <array>
#include <cstdint>
#include <iostream>
#include <string>
int main(int argc,char**argv) {
  if(argc!=3){std::cerr<<"usage: lifecycle ENCLAVE MODE\n";return 2;}
  sgx_enclave_id_t eid=0;
  sgx_launch_token_t token={0};
  int updated=0;
  sgx_status_t s=sgx_create_enclave(argv[1],SGX_DEBUG_FLAG,&token,&updated,&eid,nullptr);
  if(s!=SGX_SUCCESS){std::cerr<<"sgx_create_enclave failed: 0x"<<std::hex<<s<<"\n";return 1;}
  std::string enclave=argv[1];uint8_t role=enclave.find("csp")!=std::string::npos?2:
    enclave.find("cp")!=std::string::npos?1:0;
  std::array<uint8_t,8> request{{'S','O','C','I',1,
    uint8_t(std::string(argv[2])=="SIM"?1:2),role,0}};
  uint32_t result=UINT32_MAX;
  s=ecall_initialize(eid,&result,request.data(),request.size());
  if(s!=SGX_SUCCESS||result!=0){std::cerr<<"ecall_initialize failed\n";sgx_destroy_enclave(eid);return 1;}
  s=ecall_close(eid,&result);
  if(s!=SGX_SUCCESS||result!=0){std::cerr<<"ecall_close failed\n";sgx_destroy_enclave(eid);return 1;}
  s=sgx_destroy_enclave(eid);
  if(s!=SGX_SUCCESS){std::cerr<<"sgx_destroy_enclave failed\n";return 1;}
  std::cout<<"SGX "<<argv[2]<<" lifecycle passed: "<<argv[1]<<"\n";
}
