/* SPDX-License-Identifier: BSD-2-Clause. See HVFDOS-LICENSE.txt. */
#include "hvf_lifecycle.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
struct fake { int fail; char calls[128]; unsigned count; };
static int call(void *p, int n) {
  struct fake *f = p;
  assert(f->count < sizeof(f->calls)-1);
  f->calls[f->count++] = (char)('0'+n);
  return f->fail == n;
}
#define OP(name, n) static int name(void *p) { return call(p,n); }
OP(create_vm,1) OP(map,2) OP(create_cpu,3) OP(destroy_cpu,4) OP(unmap,5) OP(destroy_vm,6)
static void release(void *p) { assert(call(p,7)==0); }
static struct hvf_resources make(struct fake *f) {
  return (struct hvf_resources){.backing=true,.context=f,.operations={
    create_vm,map,create_cpu,destroy_cpu,unmap,destroy_vm,release}};
}
int main(void) {
  for (int fail=0; fail<=6; ++fail) {
    struct fake f={.fail=fail}; struct hvf_resources r=make(&f);
    bool ready=hvf_start_vm(&r) && hvf_start_iteration(&r);
    assert(ready==(fail==0 || fail>=4));
    if (!ready) assert(!hvf_start_iteration(&r)); /* no re-entry after failure */
    bool cleaned=hvf_finish_resources(&r);
    const char *expected[]={"1234567","17","1267","123567","1234","12345","123456"};
    assert(strcmp(f.calls,expected[fail])==0);
    assert(cleaned==(fail<4));
    assert(r.backing==(fail>=4));
    assert(r.cpu==(fail==4));
    assert(r.mapping==(fail==4 || fail==5));
    assert(r.vm==(fail>=4));
    assert(r.failed==(fail!=0));
    assert(!hvf_start_iteration(&r));
    unsigned count=f.count;
    assert(hvf_finish_resources(&r)==cleaned); /* no repeated cleanup API */
    assert(f.count==count);
  }
  struct fake f={0}; struct hvf_resources r=make(&f);
  assert(hvf_start_vm(&r) && hvf_start_iteration(&r));
  assert(hvf_retire_resources(&r,false));
  assert(r.vm && r.backing && !r.cpu && !r.mapping);
  assert(hvf_start_iteration(&r));
  assert(hvf_finish_resources(&r));
  assert(strcmp(f.calls,"12345234567")==0);
  struct fake invalid={0}; r=make(&invalid);
  assert(!hvf_start_iteration(&r) && r.failed);
  assert(!hvf_start_vm(&r));
  assert(hvf_finish_resources(&r));
  assert(strcmp(invalid.calls,"7")==0);
  puts("resource success, partial initialization, teardown failure and retained-VM cases passed");
}
