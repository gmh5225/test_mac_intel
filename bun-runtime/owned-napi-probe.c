/* Authored loading and real pthread/TSFN control. No device or client inputs. */
#include <node_api.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <stdint.h>
#define CHECK(x) do {if(!(x))abort();}while(0)
static napi_threadsafe_function tsfn;
static pthread_t thread;
static _Atomic unsigned finalizers;
static void call_js(napi_env env,napi_value fn,void *context,void *data){
    (void)context;CHECK(env&&fn);napi_value receiver,value,result;
    CHECK(napi_get_undefined(env,&receiver)==napi_ok);
    CHECK(napi_create_uint32(env,(uint32_t)(uintptr_t)data,&value)==napi_ok);
    CHECK(napi_call_function(env,receiver,fn,1,&value,&result)==napi_ok);
}
static void *worker(void *unused){(void)unused;for(uintptr_t i=0;i<3;i++)CHECK(napi_call_threadsafe_function(tsfn,(void *)i,napi_tsfn_nonblocking)==napi_ok);CHECK(napi_release_threadsafe_function(tsfn,napi_tsfn_release)==napi_ok);return NULL;}
static void finalized(napi_env env,void *data,void *context){(void)env;(void)data;(void)context;CHECK(!pthread_join(thread,NULL));atomic_fetch_add(&finalizers,1);}
static napi_value start(napi_env env,napi_callback_info info){
    size_t count=1;napi_value fn,resource,result;CHECK(napi_get_cb_info(env,info,&count,&fn,NULL,NULL)==napi_ok&&count==1);
    CHECK(napi_create_string_utf8(env,"owned N-API pthread probe",NAPI_AUTO_LENGTH,&resource)==napi_ok);
    CHECK(napi_create_threadsafe_function(env,fn,NULL,resource,0,1,NULL,finalized,NULL,call_js,&tsfn)==napi_ok);
    CHECK(!pthread_create(&thread,NULL,worker,NULL));CHECK(napi_get_undefined(env,&result)==napi_ok);return result;
}
static napi_value state(napi_env env,napi_callback_info info){(void)info;napi_value result;CHECK(napi_create_uint32(env,atomic_load(&finalizers),&result)==napi_ok);return result;}
NAPI_MODULE_INIT(){napi_property_descriptor p[]={{"start",NULL,start,NULL,NULL,NULL,napi_default,NULL},{"finalizers",NULL,state,NULL,NULL,NULL,napi_default,NULL}};CHECK(napi_define_properties(env,exports,2,p)==napi_ok);return exports;}
