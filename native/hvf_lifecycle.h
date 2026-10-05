/* SPDX-License-Identifier: BSD-2-Clause. See HVFDOS-LICENSE.txt.
 * Small resource state machine for the independent HVF experiment. */
#ifndef HVF_CONTROL_LIFECYCLE_H
#define HVF_CONTROL_LIFECYCLE_H
#include <stdbool.h>

typedef int (*hvf_operation)(void *);
struct hvf_operations {
  hvf_operation create_vm, map, create_cpu, destroy_cpu, unmap, destroy_vm;
  void (*release_backing)(void *);
};
struct hvf_resources {
  bool backing, vm, mapping, cpu, failed, cleanup_failed;
  void *context;
  struct hvf_operations operations;
};
static inline bool hvf_resource_call(struct hvf_resources *r, hvf_operation op) {
  if (op(r->context) == 0) return true;
  r->failed = true;
  return false;
}
static inline bool hvf_start_vm(struct hvf_resources *r) {
  if (r->failed || !r->backing || r->vm || r->mapping || r->cpu) {
    r->failed = true; return false;
  }
  if (!hvf_resource_call(r, r->operations.create_vm)) return false;
  r->vm = true;
  return true;
}
static inline bool hvf_start_iteration(struct hvf_resources *r) {
  if (r->failed || !r->backing || !r->vm || r->mapping || r->cpu) {
    r->failed = true; return false;
  }
  if (!hvf_resource_call(r, r->operations.map)) return false;
  r->mapping = true;
  if (!hvf_resource_call(r, r->operations.create_cpu)) return false;
  r->cpu = true;
  return true;
}
/* Cleanup permits partial initialization, but never retries failed teardown.
 * A failed destroy cannot authorize unmap; failed unmap cannot authorize free. */
static inline bool hvf_retire_resources(struct hvf_resources *r, bool vm) {
  if (r->cleanup_failed) return false;
  if (r->cpu) {
    if (!hvf_resource_call(r, r->operations.destroy_cpu)) goto failed;
    r->cpu = false;
  }
  if (r->mapping) {
    if (!hvf_resource_call(r, r->operations.unmap)) goto failed;
    r->mapping = false;
  }
  if (vm && r->vm) {
    if (!hvf_resource_call(r, r->operations.destroy_vm)) goto failed;
    r->vm = false;
  }
  return true;
failed:
  r->cleanup_failed = true;
  return false;
}
static inline bool hvf_finish_resources(struct hvf_resources *r) {
  if (!hvf_retire_resources(r, true)) return false;
  if (r->backing) {
    r->operations.release_backing(r->context);
    r->backing = false;
  }
  return true;
}
#endif
