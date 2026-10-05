/* SPDX-License-Identifier: BSD-2-Clause. See HVFDOS-LICENSE.txt.
 * Real-mode segment setup adapted from pmdj/hvf-edge-cases at
 * f150b38bfff419fe19907b7a6a2d743a63b46a49 (hvdos developers, 2009-2010).
 * Authored derivative: finite timer/store witness, one owner, bounded VM/vCPU
 * lifetime comparison. Not the unchanged upstream DOS/interrupt experiment.
 */
#if !defined(__APPLE__) || !defined(__x86_64__)
#error This experiment must be built for native Intel macOS
#endif
#include "hvf_lifecycle.h"
#include <Hypervisor/hv.h>
#include <Hypervisor/hv_vmx.h>
#include <mach/mach_time.h>
#include <sys/sysctl.h>
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MEMORY_BYTES 65536u
#define ITERATIONS 1000u
#define SLICE_NS UINT64_C(5000000)
#define BUDGET_NS UINT64_C(2000000000)
#define CALL_LIMIT 4096u
#define EVENT_LIMIT 65536u
static struct {
  void *memory;
  hv_vcpuid_t cpu;
  uint64_t owner, sequence, vm_generation, cpu_generation;
  unsigned iteration;
  mach_timebase_info_data_t timebase;
} g;
static uint64_t owner(void) {
  uint64_t value=0;
  if (pthread_threadid_np(NULL,&value) || !value || (g.owner && value!=g.owner)) {
    fputs("owner identity failure\n",stderr); exit(2);
  }
  return value;
}
static void begin_event(const char *kind) {
  if (g.sequence >= EVENT_LIMIT) {
    fputs("native evidence event limit exceeded\n",stderr); _Exit(3);
  }
  printf("{\"event\":\"%s\",\"seq\":%"PRIu64",\"iteration\":%u,\"owner\":%"PRIu64
         ",\"vm_generation\":%"PRIu64",\"cpu_generation\":%"PRIu64,
         kind,++g.sequence,g.iteration,owner(),g.vm_generation,g.cpu_generation);
}
static void end_event(void) {
  if (puts("}")==EOF || fflush(stdout)) _Exit(3);
}
static void event(const char *kind,const char *format,...) {
  begin_event(kind);
  va_list args; va_start(args,format); vprintf(format,args); va_end(args);
  end_event();
}
static bool error(const char *operation,uint64_t status) {
  event("error",",\"operation\":\"%s\",\"status\":%"PRIu64,operation,status);
  return false;
}
static bool checked(hv_return_t status,const char *operation) {
  return status==HV_SUCCESS || error(operation,(uint32_t)status);
}
static int lifecycle(void *unused,const char *name) {
  (void)unused;
  event("resource",",\"operation\":\"%s\",\"phase\":\"begin\"",name);
  hv_return_t status=HV_ERROR;
  if (!strcmp(name,"vm_create")) {
    status=hv_vm_create(HV_VM_DEFAULT);
    if (!status) ++g.vm_generation;
  } else if (!strcmp(name,"map")) {
    status=hv_vm_map(g.memory,0,MEMORY_BYTES,HV_MEMORY_READ|HV_MEMORY_WRITE|HV_MEMORY_EXEC);
  } else if (!strcmp(name,"cpu_create")) {
    status=hv_vcpu_create(&g.cpu,HV_VCPU_DEFAULT);
    if (!status) ++g.cpu_generation;
  } else if (!strcmp(name,"cpu_destroy")) status=hv_vcpu_destroy(g.cpu);
  else if (!strcmp(name,"unmap")) status=hv_vm_unmap(0,MEMORY_BYTES);
  else if (!strcmp(name,"vm_destroy")) status=hv_vm_destroy();
  event("resource",",\"operation\":\"%s\",\"phase\":\"end\",\"status\":%u",name,(uint32_t)status);
  return status!=HV_SUCCESS;
}
#define OP(function,name) static int function(void *p) { return lifecycle(p,name); }
OP(create_vm,"vm_create") OP(map,"map") OP(create_cpu,"cpu_create")
OP(destroy_cpu,"cpu_destroy") OP(unmap,"unmap") OP(destroy_vm,"vm_destroy")
static void release_backing(void *unused) {
  (void)unused; free(g.memory); g.memory=NULL;
  event("backing_released","");
}
static bool write_field(uint32_t field,uint64_t value) {
  return checked(hv_vmx_vcpu_write_vmcs(g.cpu,field,value),"write_vmcs");
}
static bool read_field(uint32_t field,uint64_t *value) {
  return checked(hv_vmx_vcpu_read_vmcs(g.cpu,field,value),"read_vmcs");
}
static bool set_register(hv_x86_reg_t reg,uint64_t value) {
  return checked(hv_vcpu_write_register(g.cpu,reg,value),"write_register");
}
static bool get_register(hv_x86_reg_t reg,uint64_t *value) {
  return checked(hv_vcpu_read_register(g.cpu,reg,value),"read_register");
}
static bool control(uint32_t field,uint64_t required,uint64_t forbidden) {
  uint64_t must=0,may=0,observed=0;
  if (!checked(hv_vmx_vcpu_get_cap_write_vmcs(g.cpu,field,&must,&may),"control_capability")) return false;
  if ((must&~may) || (required&may)!=required || (must&forbidden)) return error("unsupported_control",field);
  uint64_t effective=must|required;
  if (!write_field(field,effective) || !read_field(field,&observed)) return false;
  if (effective!=observed) return error("control_readback",field);
  event("control",",\"field\":%u,\"required\":%"PRIu64",\"forbidden\":%"PRIu64
        ",\"must\":%"PRIu64",\"may\":%"PRIu64",\"effective\":%"PRIu64",\"observed\":%"PRIu64,
        field,required,forbidden,must,may,effective,observed);
  return true;
}
static bool control_register(uint32_t field,uint64_t requested,uint64_t forbidden,uint64_t *value) {
  bool cr4=field==VMCS_GUEST_CR4;
  uint64_t must=0,may=0,fixed=0,allowed=0,observed=0;
  if (!checked(hv_vmx_vcpu_get_cap_write_vmcs(g.cpu,field,&must,&may),"register_capability") ||
      !checked(hv_vmx_read_capability(cr4?HV_VMX_CAP_CR4_FIXED0:HV_VMX_CAP_CR0_FIXED0,&fixed),"fixed0") ||
      !checked(hv_vmx_read_capability(cr4?HV_VMX_CAP_CR4_FIXED1:HV_VMX_CAP_CR0_FIXED1,&allowed),"fixed1")) return false;
  /* Unrestricted guest relaxes the hardware CR0.PE/PG fixed-one requirements.
   * Framework writable constraints remain mandatory and are never masked. */
  uint64_t relaxed=cr4?fixed:(fixed&~UINT64_C(0x80000001));
  *value=requested|must|relaxed;
  if ((must&~may) || (*value&~(may&allowed)) || (*value&forbidden)) return error("unsupported_control_register",field);
  if (!write_field(field,*value) || !read_field(field,&observed)) return false;
  if (observed!=*value) return error("control_register_readback",field);
  event("control_register",",\"field\":%u,\"requested\":%"PRIu64",\"forbidden\":%"PRIu64
        ",\"must\":%"PRIu64",\"may\":%"PRIu64",\"fixed\":%"PRIu64",\"allowed\":%"PRIu64
        ",\"effective\":%"PRIu64",\"observed\":%"PRIu64,
        field,requested,forbidden,must,may,fixed,allowed,*value,observed);
  return true;
}
struct field { uint32_t id; uint64_t value; };
static bool prepare(uint16_t nonce) {
  if (!control(VMCS_CTRL_PIN_BASED,PIN_BASED_INTR|PIN_BASED_NMI,0) ||
      !control(VMCS_CTRL_CPU_BASED,CPU_BASED_SECONDARY_CTLS|CPU_BASED_HLT,CPU_BASED_MTF|CPU_BASED_TPR_SHADOW) ||
      !control(VMCS_CTRL_CPU_BASED2,CPU_BASED2_EPT|CPU_BASED2_UNRESTRICTED,0) ||
      !control(VMCS_CTRL_VMENTRY_CONTROLS,VMENTRY_LOAD_EFER,VMENTRY_GUEST_IA32E)) return false;
  uint64_t cr0,cr4;
  if (!control_register(VMCS_GUEST_CR0,0x20,UINT64_C(0x80000001),&cr0) ||
      !control_register(VMCS_GUEST_CR4,0x2000,0x20,&cr4)) return false;
  struct field fields[64]; unsigned count=0;
#define FIELD(id,val) fields[count++]=(struct field){id,val}
  FIELD(VMCS_CTRL_EXC_BITMAP,UINT32_MAX); FIELD(VMCS_CTRL_PF_ERROR_MASK,0);
  FIELD(VMCS_CTRL_PF_ERROR_MATCH,0); FIELD(VMCS_CTRL_VMENTRY_IRQ_INFO,0);
  FIELD(VMCS_CTRL_CR0_MASK,0x60000000); FIELD(VMCS_CTRL_CR0_SHADOW,0);
  FIELD(VMCS_CTRL_CR4_MASK,0); FIELD(VMCS_CTRL_CR4_SHADOW,0);
  FIELD(VMCS_CTRL_CR3_COUNT,0); FIELD(VMCS_CTRL_TPR_THRESHOLD,0);
  FIELD(VMCS_GUEST_ACTIVITY_STATE,0); FIELD(VMCS_GUEST_INTERRUPTIBILITY,0);
  FIELD(VMCS_GUEST_DEBUG_EXC,0); FIELD(VMCS_GUEST_DR7,0x400);
  FIELD(VMCS_GUEST_IA32_EFER,0); FIELD(VMCS_GUEST_CR3,0);
  FIELD(VMCS_GUEST_GDTR_BASE,0); FIELD(VMCS_GUEST_GDTR_LIMIT,0);
  FIELD(VMCS_GUEST_IDTR_BASE,0); FIELD(VMCS_GUEST_IDTR_LIMIT,0);
  FIELD(VMCS_GUEST_LDTR,0); FIELD(VMCS_GUEST_LDTR_BASE,0);
  FIELD(VMCS_GUEST_LDTR_LIMIT,0); FIELD(VMCS_GUEST_LDTR_AR,0x10000);
  FIELD(VMCS_GUEST_TR,0); FIELD(VMCS_GUEST_TR_BASE,0);
  FIELD(VMCS_GUEST_TR_LIMIT,0); FIELD(VMCS_GUEST_TR_AR,0x83);
  for (unsigned n=0;n<6;++n) {
    FIELD(VMCS_GUEST_ES+2*n,0); FIELD(VMCS_GUEST_ES_BASE+2*n,0);
    FIELD(VMCS_GUEST_ES_LIMIT+2*n,0xffff);
    FIELD(VMCS_GUEST_ES_AR+2*n,n==1?0x9b:0x93);
  }
  FIELD(VMCS_GUEST_RIP,0x100); FIELD(VMCS_GUEST_RFLAGS,2);
#undef FIELD
  if (count>64) return error("state_capacity",count);
  for (unsigned n=0;n<count;++n) {
    uint64_t readback=0;
    if (!write_field(fields[n].id,fields[n].value) || !read_field(fields[n].id,&readback)) return false;
    if (readback!=fields[n].value) return error("state_readback",fields[n].id);
  }
  const hv_x86_reg_t registers[]={HV_X86_RAX,HV_X86_RBX,HV_X86_RCX,HV_X86_RDX,
    HV_X86_RSI,HV_X86_RDI,HV_X86_RBP,HV_X86_RSP,HV_X86_R8,HV_X86_R9,HV_X86_R10,
    HV_X86_R11,HV_X86_R12,HV_X86_R13,HV_X86_R14,HV_X86_R15};
  for (unsigned n=0;n<sizeof(registers)/sizeof(registers[0]);++n) {
    uint64_t desired=n==0?nonce:0,observed=0;
    if (!set_register(registers[n],desired) || !get_register(registers[n],&observed)) return false;
    if (observed!=desired) return error("gpr_readback",n);
  }
  begin_event("state");
  printf(",\"nonce\":%u,\"cr0\":%"PRIu64",\"cr4\":%"PRIu64",\"zero_other_gprs\":true,\"fields\":[",nonce,cr0,cr4);
  for (unsigned n=0;n<count;++n) printf("%s[%u,%"PRIu64"]",n?",":"",fields[n].id,fields[n].value);
  putchar(']'); end_event();
  return true;
}
static bool ticks(uint64_t ns,uint64_t *result) {
  __uint128_t wide=(__uint128_t)ns*g.timebase.denom+g.timebase.numer-1;
  wide/=g.timebase.numer;
  if (!wide || wide>=UINT64_MAX) return error("timebase_overflow",ns);
  *result=(uint64_t)wide; return true;
}
static bool future(uint64_t now,uint64_t duration,uint64_t *result) {
  if (now>=UINT64_MAX-duration) return error("deadline_overflow",duration);
  *result=now+duration; return true;
}
static bool run_finite(uint16_t nonce,_Atomic(uint16_t) *witness) {
  uint64_t slice_ticks=0,budget_ticks=0,end=0,deadline=0;
  if (!ticks(SLICE_NS,&slice_ticks) || !ticks(BUDGET_NS,&budget_ticks)) return false;
  uint64_t start=mach_absolute_time();
  if (!future(start,budget_ticks,&end) || !future(start,slice_ticks,&deadline)) return false;
  if (deadline>end) deadline=end;
  event("budget",",\"start\":%"PRIu64",\"end\":%"PRIu64",\"slice_ticks\":%"PRIu64
        ",\"budget_ticks\":%"PRIu64,start,end,slice_ticks,budget_ticks);
  bool saw_store=false;
  for (unsigned call=1;call<=CALL_LIMIT;++call) {
    uint64_t before=mach_absolute_time();
    if (before>=end) return error("budget_exhausted_before_entry",call);
    event("call_begin",",\"call\":%u,\"before\":%"PRIu64",\"deadline\":%"PRIu64,call,before,deadline);
    hv_return_t status=hv_vcpu_run_until(g.cpu,deadline);
    uint64_t after=mach_absolute_time();
    event("call_end",",\"call\":%u,\"after\":%"PRIu64",\"status\":%u",call,after,(uint32_t)status);
    if (!checked(status,"run_until")) return false;
    uint64_t reason=0,rip=0,rax=0;
    if (!read_field(VMCS_RO_EXIT_REASON,&reason) || !get_register(HV_X86_RIP,&rip) ||
        !get_register(HV_X86_RAX,&rax)) return false;
    uint16_t stored=atomic_load_explicit(witness,memory_order_seq_cst);
    uint64_t captured=mach_absolute_time();
    event("capture",",\"call\":%u,\"captured\":%"PRIu64",\"reason\":%"PRIu64
          ",\"rip\":%"PRIu64",\"rax\":%"PRIu64",\"witness\":%u",call,captured,reason,rip,rax,stored);
    if (after<before || captured<after || after>end || captured>end)
      return error("late_or_nonmonotonic_capture",call);
    if ((reason!=1 && reason!=52) || rax!=nonce ||
        !((rip==0x100 && stored==0) || (rip==0x103 && stored==nonce)))
      return error("invalid_exit_or_witness",call);
    if (saw_store && (rip!=0x103 || stored!=nonce))
      return error("guest_progress_regressed",call);
    if (stored==nonce) saw_store=true;
    if (reason==52 && rip==0x103 && stored==nonce) {
      event("witness",",\"call\":%u,\"nonce\":%u,\"captured\":%"PRIu64,call,nonce,captured);
      return true;
    }
    if (reason==52) {
      uint64_t next=0;
      if (!future(captured,slice_ticks,&next)) return false;
      deadline=next<end?next:end;
    }
    /* An IRQ keeps even an expired slice; it cannot extend the fixed budget. */
  }
  return error("call_limit",CALL_LIMIT);
}
int main(int argc,char **argv) {
  if (argc!=3 || (strcmp(argv[1],"vcpu") && strcmp(argv[1],"vm")) || strcmp(argv[2],"1000")) {
    fputs("usage: hvf-intel-real-mode {vcpu|vm} 1000\n",stderr); return 2;
  }
  bool recreate_vm=!strcmp(argv[1],"vm");
  setvbuf(stdout,NULL,_IONBF,0);
  g.owner=owner();
  int translated=0; size_t length=sizeof(translated);
  if (sysctlbyname("sysctl.proc_translated",&translated,&length,NULL,0)) {
    if (errno!=ENOENT) return 2;
  } else if (translated) return 2;
  if (mach_timebase_info(&g.timebase)!=KERN_SUCCESS || !g.timebase.numer || !g.timebase.denom) return 2;
  long page=sysconf(_SC_PAGESIZE);
  if (page<=0 || ((uint64_t)page&((uint64_t)page-1)) || MEMORY_BYTES%(uint64_t)page ||
      posix_memalign(&g.memory,(size_t)page,MEMORY_BYTES)) return 2;
  memset(g.memory,0,MEMORY_BYTES);
  const unsigned char code[]={0xa3,0x00,0x02,0xeb,0xfe};
  memcpy((unsigned char *)g.memory+0x100,code,sizeof(code));
  _Atomic(uint16_t) *witness=(_Atomic(uint16_t) *)((unsigned char *)g.memory+0x200);
  atomic_init(witness,0);
  if (!atomic_is_lock_free(witness)) { free(g.memory); return 2; }
  event("program",",\"version\":1,\"mode\":\"%s\",\"iterations\":%u,\"memory_bytes\":%u"
        ",\"guest_hex\":\"a30002ebfe\",\"timebase_numer\":%u,\"timebase_denom\":%u"
        ",\"slice_ns\":%"PRIu64",\"budget_ns\":%"PRIu64",\"call_limit\":%u,\"event_limit\":%u",
        argv[1],ITERATIONS,MEMORY_BYTES,g.timebase.numer,g.timebase.denom,SLICE_NS,BUDGET_NS,CALL_LIMIT,EVENT_LIMIT);
  struct hvf_resources resources={.backing=true,.operations={
    create_vm,map,create_cpu,destroy_cpu,unmap,destroy_vm,release_backing}};
  bool success=true;
  if (!recreate_vm) success=hvf_start_vm(&resources);
  for (g.iteration=1;success && g.iteration<=ITERATIONS;++g.iteration) {
    event("iteration_begin",",\"nonce\":%u",g.iteration);
    if (recreate_vm && !hvf_start_vm(&resources)) { success=false; break; }
    if (!hvf_start_iteration(&resources)) { success=false; break; }
    atomic_store_explicit(witness,0,memory_order_seq_cst);
    uint16_t reset=atomic_load_explicit(witness,memory_order_seq_cst);
    event("reset",",\"value\":%u",reset);
    if (reset!=0 || !prepare((uint16_t)g.iteration) || !run_finite((uint16_t)g.iteration,witness)) {
      resources.failed=true; success=false; break;
    }
    if (!hvf_retire_resources(&resources,recreate_vm)) { success=false; break; }
    event("iteration_complete",",\"nonce\":%u",g.iteration);
  }
  /* The final resource records belong to the final executed iteration. */
  if (g.iteration>ITERATIONS) g.iteration=ITERATIONS;
  if (!hvf_finish_resources(&resources)) success=false;
  if (!success || resources.failed) return 1;
  if (resources.backing || resources.mapping || resources.cpu || resources.vm) return 1;
  event("complete",",\"iterations\":%u,\"live_resources\":0",ITERATIONS);
  return 0;
}
