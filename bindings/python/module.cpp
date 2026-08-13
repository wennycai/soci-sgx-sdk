#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "soci/soci.hpp"
#include "soci/optimization.hpp"
namespace py=pybind11;
struct Ciphertext{std::vector<uint8_t> bytes;};
struct DivisionResult{Ciphertext quotient,remainder;};
PYBIND11_MODULE(_soci,m){
  py::register_exception<soci::Error>(m,"SociException");
  py::register_exception<soci::optimization::OptimizationError>(m,"OptimizationError");
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
  using namespace soci::optimization;
  py::enum_<Status>(m,"OptimizationStatus")
    .value("OPTIMAL",Status::optimal).value("INVALID_ARGUMENT",Status::invalid_argument)
    .value("NO_FEASIBLE_SOLUTION",Status::no_feasible_solution)
    .value("NUMERIC_RANGE_EXCEEDED",Status::numeric_range_exceeded);
  py::class_<OptimizationResult>(m,"OptimizationResult")
    .def_readonly("total_cost",&OptimizationResult::total_cost)
    .def_readonly("ratio",&OptimizationResult::ratio)
    .def_readonly("solution",&OptimizationResult::solution)
    .def_readonly("status",&OptimizationResult::status);
  auto matrix=[](const py::iterable& rows){
    CostMatrix out;
    for(py::handle item:rows){
      py::sequence row=py::reinterpret_borrow<py::sequence>(item);
      if(py::len(row)!=3)throw OptimizationError(Status::invalid_argument,"every cost row must have exactly three columns");
      CostRow converted;
      for(int j=0;j<3;j++)if(!row[j].is_none())converted[j]=py::str(row[j]).cast<std::string>();
      out.push_back(std::move(converted));
    }
    return out;
  };
  py::class_<Optimizer>(m,"Optimizer")
    .def(py::init<soci::Runtime&>(),py::keep_alive<1,2>())
    .def("optimize",[matrix](const Optimizer&o,const py::iterable& costs,py::object threshold){
      return o.optimize(matrix(costs),py::str(threshold).cast<std::string>());
    },py::arg("costs"),py::arg("ratio_threshold")=0.6)
    .def("optimize_csv",[](const Optimizer&o,const std::string& path,py::object threshold){
      return o.optimize_csv(path,py::str(threshold).cast<std::string>());
    },py::arg("path"),py::arg("ratio_threshold")=0.6);
  m.def("optimize_plain",[matrix](const py::iterable& costs,py::object threshold){
    return optimize_plain(matrix(costs),py::str(threshold).cast<std::string>());
  },py::arg("costs"),py::arg("ratio_threshold")=0.6);
  m.def("optimize_csv_plain",[](const std::string& path,py::object threshold){
    return optimize_csv_plain(path,py::str(threshold).cast<std::string>());
  },py::arg("path"),py::arg("ratio_threshold")=0.6);
  m.attr("SociPublicClient")=m.attr("SociRuntime");m.attr("SociCpClient")=m.attr("SociRuntime");m.attr("SociCspService")=m.attr("SociRuntime");
}
