#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "soci/soci.hpp"
namespace py=pybind11;
struct Ciphertext{std::vector<uint8_t> bytes;};
struct DivisionResult{Ciphertext quotient,remainder;};
PYBIND11_MODULE(_soci,m){
  py::register_exception<soci::Error>(m,"SociException");
  py::class_<Ciphertext>(m,"Ciphertext").def(py::init<>()).def(py::init([](py::bytes b){std::string s=b;return Ciphertext{{s.begin(),s.end()}};})).def("to_bytes",[](const Ciphertext&c){return py::bytes((char*)c.bytes.data(),c.bytes.size());});
  py::class_<DivisionResult>(m,"DivisionResult")
    .def_readonly("quotient",&DivisionResult::quotient)
    .def_readonly("remainder",&DivisionResult::remainder);
  py::class_<soci::Runtime>(m,"SociRuntime").def(py::init<const std::string&>()).def("create_key",&soci::Runtime::create_key,py::arg("key_id"),py::arg("bits")=SOCI_SECURITY_128_MODULUS_BITS).def("open_key",&soci::Runtime::open_key)
    .def("encrypt",[](soci::Runtime&r,py::object v){return Ciphertext{r.encrypt(py::str(v))};})
    .def("decrypt",[](soci::Runtime&r,const Ciphertext&c){py::gil_scoped_release u;return r.decrypt(c.bytes);})
    .def("add",[](soci::Runtime&r,const Ciphertext&a,const Ciphertext&b){return Ciphertext{r.add(a.bytes,b.bytes)};})
    .def("scalar_mul",[](soci::Runtime&r,const Ciphertext&a,py::object k){return Ciphertext{r.scalar_mul(a.bytes,py::str(k))};})
    .def("secure_mul",[](soci::Runtime&r,const Ciphertext&a,const Ciphertext&b){return Ciphertext{r.secure_mul(a.bytes,b.bytes)};})
    .def("secure_compare",[](soci::Runtime&r,const Ciphertext&a,const Ciphertext&b){return Ciphertext{r.secure_compare(a.bytes,b.bytes)};})
    .def("secure_sign_bit",[](soci::Runtime&r,const Ciphertext&a){return Ciphertext{r.secure_sign_bit(a.bytes)};})
    .def("secure_abs",[](soci::Runtime&r,const Ciphertext&a){return Ciphertext{r.secure_abs(a.bytes)};})
    .def("secure_div",[](soci::Runtime&r,const Ciphertext&a,const Ciphertext&b){auto q=r.secure_div(a.bytes,b.bytes);return DivisionResult{Ciphertext{std::move(q.first)},Ciphertext{std::move(q.second)}};})
    .def("__enter__",[](soci::Runtime&r)->soci::Runtime&{return r;},py::return_value_policy::reference).def("__exit__",[](soci::Runtime&,py::object,py::object,py::object){});
  m.attr("SociPublicClient")=m.attr("SociRuntime");m.attr("SociCpClient")=m.attr("SociRuntime");m.attr("SociCspService")=m.attr("SociRuntime");
}
