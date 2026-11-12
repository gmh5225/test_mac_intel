#include "cs_priv.h"
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { num_threads = 24 };
static size_t lookup_bytes;
static uint32_t *oracle, *reg_oracle;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t condition = PTHREAD_COND_INITIALIZER;
static unsigned arrived, published, private_count;
static uint32_t *shared_insn, *shared_regs;

static void *private_malloc(size_t size) { return malloc(size); }
static void verify(cs_struct *h) {
  if (sizeof(uint32_t) * ((size_t)h->x86_insn_lut_max + 1) != lookup_bytes ||
      !h->x86_insn_lut || !h->x86_insn_reg_lut ||
      memcmp(oracle, h->x86_insn_lut, lookup_bytes) ||
      memcmp(reg_oracle, h->x86_insn_reg_lut, lookup_bytes)) abort();
}
static void *worker(void *instance) {
  uintptr_t n = (uintptr_t)instance;
  pthread_mutex_lock(&mutex);
  if (++arrived == num_threads) pthread_cond_broadcast(&condition);
  while (arrived < num_threads) pthread_cond_wait(&condition, &mutex);
  pthread_mutex_unlock(&mutex);
  for (unsigned i=0; i<32; ++i) {
    csh handle; cs_mode mode = (n+i)%3==0 ? CS_MODE_16 : ((n+i)%3==1 ? CS_MODE_32 : CS_MODE_64);
    if (cs_open(CS_ARCH_X86,mode,&handle)) abort();
    cs_struct *h = (cs_struct *)(uintptr_t)handle;
    verify(h);
    pthread_mutex_lock(&mutex);
    if (h->x86_shared_lookups) {
      if (shared_insn && (shared_insn!=h->x86_insn_lut || shared_regs!=h->x86_insn_reg_lut)) abort();
      ++published; shared_insn=h->x86_insn_lut; shared_regs=h->x86_insn_reg_lut;
    } else ++private_count;
    pthread_mutex_unlock(&mutex);
    if (cs_close(&handle)) abort();
  }
  return NULL;
}
int main(void) {
  cs_opt_mem system_hooks={cs_mem_malloc,cs_mem_calloc,cs_mem_realloc,cs_mem_free,cs_vsnprintf};
  cs_opt_mem hooks=system_hooks;hooks.malloc=private_malloc;
  cs_arch_register_x86();
  if(cs_option(0,CS_OPT_MEM,(size_t)&hooks))return 1;
  csh reference;
  if(cs_open(CS_ARCH_X86,CS_MODE_32,&reference))return 2;
  cs_struct *h=(cs_struct *)(uintptr_t)reference;
  if(h->x86_shared_lookups)return 3;
  lookup_bytes=(h->x86_insn_lut_max+1)*sizeof(uint32_t);oracle=malloc(lookup_bytes);reg_oracle=malloc(lookup_bytes);
  if(!oracle || !reg_oracle)return 4;
  memcpy(oracle,h->x86_insn_lut,lookup_bytes);memcpy(reg_oracle,h->x86_insn_reg_lut,lookup_bytes);
  if(cs_close(&reference)||cs_option(0,CS_OPT_MEM,(size_t)&system_hooks))return 5;
  pthread_t threads[num_threads];
  for(uintptr_t i=0;i<num_threads;i++)if(pthread_create(&threads[i],NULL,worker,(void*)i))return 6;
  for(unsigned i=0;i<num_threads;i++)if(pthread_join(threads[i],NULL))return 7;
  if(published+private_count!=32*num_threads || private_count>=num_threads)return 8;
  if(cs_option(0,CS_OPT_MEM,(size_t)&hooks)||cs_open(CS_ARCH_X86,CS_MODE_64,&reference))return 9;
  h=(cs_struct *)(uintptr_t)reference;verify(h);if(h->x86_shared_lookups)return 10;
  cs_close(&reference);cs_option(0,CS_OPT_MEM,(size_t)&system_hooks);
  printf("{\"threads\":%u,\"shared\":%u,\"private\":%u,\"entries\":%zu}\n",num_threads,published,private_count,lookup_bytes/4);
  free(oracle);free(reg_oracle);
}
