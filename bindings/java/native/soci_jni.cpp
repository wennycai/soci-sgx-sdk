#include <jni.h>
#include "soci/soci.h"
#include "soci/soci.hpp"
#include "soci/optimization.hpp"
#include <cmath>
#include <string>
#include <vector>
static void fail(JNIEnv*e,const char*m){jclass c=e->FindClass("com/soci/sdk/SociException");e->ThrowNew(c,m);}
extern "C" JNIEXPORT jlong JNICALL Java_com_soci_sdk_SociRuntime_nativeCreate(JNIEnv*e,jclass,jstring d){const char*s=e->GetStringUTFChars(d,nullptr);soci_runtime_t*r=nullptr;auto rc=soci_runtime_create(s,&r);e->ReleaseStringUTFChars(d,s);if(rc){fail(e,"runtime create failed");return 0;}return (jlong)r;}
extern "C" JNIEXPORT void JNICALL Java_com_soci_sdk_SociRuntime_nativeClose(JNIEnv*,jclass,jlong h){soci_runtime_close((soci_runtime_t*)h);}
extern "C" JNIEXPORT void JNICALL Java_com_soci_sdk_SociRuntime_nativeCreateKey(JNIEnv*e,jclass,jlong h,jstring id,jint bits){const char*s=e->GetStringUTFChars(id,nullptr);auto rc=soci_create_key((soci_runtime_t*)h,s,bits,SOCI_ROLE_FULL);e->ReleaseStringUTFChars(id,s);if(rc)fail(e,soci_runtime_get_last_error((soci_runtime_t*)h));}
extern "C" JNIEXPORT jstring JNICALL Java_com_soci_sdk_SociRuntime_nativeDecrypt(JNIEnv*e,jclass,jlong h,jbyteArray a){jsize l=e->GetArrayLength(a);std::string b(l,0);e->GetByteArrayRegion(a,0,l,(jbyte*)b.data());size_t n=0;soci_decrypt((soci_runtime_t*)h,(uint8_t*)b.data(),l,nullptr,&n);std::string o(n,0);auto rc=soci_decrypt((soci_runtime_t*)h,(uint8_t*)b.data(),l,o.data(),&n);if(rc){fail(e,soci_runtime_get_last_error((soci_runtime_t*)h));return nullptr;}return e->NewStringUTF(o.c_str());}
static std::vector<uint8_t> bytes(JNIEnv*e,jbyteArray a){std::vector<uint8_t>b(e->GetArrayLength(a));e->GetByteArrayRegion(a,0,b.size(),(jbyte*)b.data());return b;}
static jbyteArray array(JNIEnv*e,const std::vector<uint8_t>&b){auto a=e->NewByteArray(b.size());e->SetByteArrayRegion(a,0,b.size(),(const jbyte*)b.data());return a;}
template<class F>static jbyteArray output(JNIEnv*e,soci_runtime_t*h,F f){size_t n=0;auto rc=f(nullptr,&n);if(rc!=SOCI_BUFFER_TOO_SMALL){fail(e,soci_runtime_get_last_error(h));return nullptr;}for(int i=0;i<3;i++){std::vector<uint8_t>o(n);rc=f(o.data(),&n);if(rc==SOCI_OK){o.resize(n);return array(e,o);}if(rc!=SOCI_BUFFER_TOO_SMALL){fail(e,soci_runtime_get_last_error(h));return nullptr;}}fail(e,"output size changed repeatedly");return nullptr;}
extern "C" JNIEXPORT jbyteArray JNICALL Java_com_soci_sdk_SociRuntime_nativeEncrypt(JNIEnv*e,jclass,jlong x,jstring m){auto*h=(soci_runtime_t*)x;const char*s=e->GetStringUTFChars(m,nullptr);auto r=output(e,h,[&](uint8_t*o,size_t*n){return soci_encrypt(h,s,o,n);});e->ReleaseStringUTFChars(m,s);return r;}
extern "C" JNIEXPORT jbyteArray JNICALL Java_com_soci_sdk_SociRuntime_nativeBinary(JNIEnv*e,jclass,jlong x,jint op,jbyteArray aa,jbyteArray ab){auto*h=(soci_runtime_t*)x;auto a=bytes(e,aa),b=bytes(e,ab);return output(e,h,[&](uint8_t*o,size_t*n){if(op==0)return soci_add(h,a.data(),a.size(),b.data(),b.size(),o,n);if(op==1)return soci_secure_mul(h,a.data(),a.size(),b.data(),b.size(),o,n);return soci_secure_compare(h,a.data(),a.size(),b.data(),b.size(),o,n);});}
extern "C" JNIEXPORT jbyteArray JNICALL Java_com_soci_sdk_SociRuntime_nativeUnary(JNIEnv*e,jclass,jlong x,jint op,jbyteArray aa){auto*h=(soci_runtime_t*)x;auto a=bytes(e,aa);return output(e,h,[&](uint8_t*o,size_t*n){return op?soci_secure_abs(h,a.data(),a.size(),o,n):soci_secure_sign_bit(h,a.data(),a.size(),o,n);});}
extern "C" JNIEXPORT jbyteArray JNICALL Java_com_soci_sdk_SociRuntime_nativeScalarMul(JNIEnv*e,jclass,jlong x,jbyteArray aa,jstring kk){auto*h=(soci_runtime_t*)x;auto a=bytes(e,aa);const char*k=e->GetStringUTFChars(kk,nullptr);auto r=output(e,h,[&](uint8_t*o,size_t*n){return soci_scalar_mul(h,a.data(),a.size(),k,o,n);});e->ReleaseStringUTFChars(kk,k);return r;}
extern "C" JNIEXPORT jobjectArray JNICALL Java_com_soci_sdk_SociRuntime_nativeDiv(JNIEnv*e,jclass,jlong x,jbyteArray aa,jbyteArray ab){auto*h=(soci_runtime_t*)x;auto a=bytes(e,aa),b=bytes(e,ab);size_t qn=0,rn=0;auto rc=soci_secure_div(h,a.data(),a.size(),b.data(),b.size(),nullptr,&qn,nullptr,&rn);if(rc!=SOCI_BUFFER_TOO_SMALL){fail(e,soci_runtime_get_last_error(h));return nullptr;}std::vector<uint8_t>q(qn),r(rn);rc=soci_secure_div(h,a.data(),a.size(),b.data(),b.size(),q.data(),&qn,r.data(),&rn);if(rc){fail(e,soci_runtime_get_last_error(h));return nullptr;}jclass bc=e->FindClass("[B");jobjectArray out=e->NewObjectArray(2,bc,nullptr);e->SetObjectArrayElement(out,0,array(e,q));e->SetObjectArrayElement(out,1,array(e,r));return out;}
extern "C" JNIEXPORT jobject JNICALL Java_com_soci_sdk_SociRuntime_nativeOptimize(JNIEnv*e,jclass,jlong x,jobjectArray rows,jdouble threshold){
  try{
    soci::optimization::CostMatrix matrix;
    jsize n=e->GetArrayLength(rows);
    jclass number=e->FindClass("java/lang/Number");
    jmethodID doubleValue=e->GetMethodID(number,"doubleValue","()D");
    for(jsize i=0;i<n;i++){
      auto row=(jobjectArray)e->GetObjectArrayElement(rows,i);
      if(!row||e->GetArrayLength(row)!=3)throw std::invalid_argument("every cost row must have exactly three columns");
      soci::optimization::CostRow converted;
      for(jsize j=0;j<3;j++){
        jobject value=e->GetObjectArrayElement(row,j);
        if(value){double v=e->CallDoubleMethod(value,doubleValue);if(!std::isfinite(v))throw std::invalid_argument("cost must be finite");converted[j]=std::to_string(v);e->DeleteLocalRef(value);}
      }
      matrix.push_back(std::move(converted));e->DeleteLocalRef(row);
    }
    auto runtime=soci::Runtime::borrowed(reinterpret_cast<soci_runtime_t*>(x));
    auto result=soci::optimization::Optimizer(runtime).optimize(matrix,std::to_string(threshold));
    jintArray solution=e->NewIntArray(result.solution.size());
    e->SetIntArrayRegion(solution,0,result.solution.size(),reinterpret_cast<const jint*>(result.solution.data()));
    jclass cls=e->FindClass("com/soci/sdk/OptimizationResult");
    jmethodID ctor=e->GetMethodID(cls,"<init>","(DD[I)V");
    return e->NewObject(cls,ctor,result.total_cost,result.ratio,solution);
  }catch(const std::exception& ex){fail(e,ex.what());return nullptr;}
}
extern "C" JNIEXPORT jobject JNICALL Java_com_soci_sdk_SociRuntime_nativeOptimizeCsv(JNIEnv*e,jclass,jlong x,jstring path,jdouble threshold){
  const char* chars=e->GetStringUTFChars(path,nullptr);
  try{
    auto runtime=soci::Runtime::borrowed(reinterpret_cast<soci_runtime_t*>(x));
    auto result=soci::optimization::Optimizer(runtime).optimize_csv(chars,std::to_string(threshold));
    e->ReleaseStringUTFChars(path,chars);
    jintArray solution=e->NewIntArray(result.solution.size());
    e->SetIntArrayRegion(solution,0,result.solution.size(),reinterpret_cast<const jint*>(result.solution.data()));
    jclass cls=e->FindClass("com/soci/sdk/OptimizationResult");
    jmethodID ctor=e->GetMethodID(cls,"<init>","(DD[I)V");
    return e->NewObject(cls,ctor,result.total_cost,result.ratio,solution);
  }catch(const std::exception& ex){e->ReleaseStringUTFChars(path,chars);fail(e,ex.what());return nullptr;}
}
extern "C" JNIEXPORT jobjectArray JNICALL Java_com_soci_sdk_SociRuntime_nativeOptimizeEncrypted(JNIEnv*e,jclass,jlong x,jobjectArray rows,jdouble threshold){
  try{
    std::vector<std::array<std::optional<std::vector<uint8_t>>,3>> matrix;
    jsize n=e->GetArrayLength(rows);matrix.resize(n);
    for(jsize i=0;i<n;i++){
      auto row=(jobjectArray)e->GetObjectArrayElement(rows,i);
      if(!row||e->GetArrayLength(row)!=3)throw std::invalid_argument("every encrypted row must have three columns");
      for(jsize j=0;j<3;j++){auto value=(jbyteArray)e->GetObjectArrayElement(row,j);if(value){matrix[i][j]=bytes(e,value);e->DeleteLocalRef(value);}}
      e->DeleteLocalRef(row);
    }
    auto runtime=soci::Runtime::borrowed(reinterpret_cast<soci_runtime_t*>(x));
    auto result=soci::optimization::Optimizer(runtime).optimize_encrypted(matrix,std::to_string(threshold));
    std::vector<std::vector<uint8_t>> values;values.push_back(std::move(result.total_cost));values.push_back(std::move(result.c12));values.push_back(std::move(result.c3));
    for(auto&v:result.solution)values.push_back(std::move(v));
    jclass bc=e->FindClass("[B");jobjectArray out=e->NewObjectArray(values.size(),bc,nullptr);
    for(size_t i=0;i<values.size();i++)e->SetObjectArrayElement(out,i,array(e,values[i]));return out;
  }catch(const std::exception&ex){fail(e,ex.what());return nullptr;}
}
