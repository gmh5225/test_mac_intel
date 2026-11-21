/* Execute a hash-checked Multiboot fixture on one KVM vCPU. */
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

enum { RamBytes = 32 * 1024 * 1024, CpuidEntries = 512 };

static void fail(const char *message) {
  perror(message);
  exit(2);
}

static int request(int fd, unsigned long op, unsigned long arg, const char *name) {
  int result;
  do {
    result = ioctl(fd, op, arg);
  } while (result < 0 && errno == EINTR);
  if (result < 0)
    fail(name);
  return result;
}
#define KVM(fd, op, arg) request(fd, op, (unsigned long)(arg), #op)

static uint32_t load_guest(const char *path, uint8_t *ram) {
  int file = open(path, O_RDONLY);
  struct stat info;
  if (file < 0 || fstat(file, &info) || info.st_size < (off_t)sizeof(Elf32_Ehdr))
    fail("guest image");
  size_t size = (size_t)info.st_size;
  const uint8_t *image = mmap(NULL, size, PROT_READ, MAP_PRIVATE, file, 0);
  if (image == MAP_FAILED)
    fail("map image");
  const Elf32_Ehdr *elf = (const Elf32_Ehdr *)image;
  if (memcmp(elf->e_ident, ELFMAG, SELFMAG) || elf->e_ident[EI_CLASS] != ELFCLASS32 ||
      elf->e_ident[EI_DATA] != ELFDATA2LSB || elf->e_machine != EM_386 ||
      elf->e_phentsize != sizeof(Elf32_Phdr) || elf->e_phoff > size ||
      (size_t)elf->e_phnum * sizeof(Elf32_Phdr) > size - elf->e_phoff ||
      elf->e_entry >= RamBytes) {
    fputs("Invalid Multiboot image\n", stderr);
    exit(2);
  }
  for (unsigned i = 0; i < elf->e_phnum; ++i) {
    Elf32_Phdr seg;
    memcpy(&seg, image + elf->e_phoff + i * sizeof(seg), sizeof(seg));
    if (seg.p_type != PT_LOAD)
      continue;
    if (seg.p_filesz > seg.p_memsz || seg.p_offset > size ||
        seg.p_filesz > size - seg.p_offset || seg.p_paddr > RamBytes ||
        seg.p_memsz > RamBytes - seg.p_paddr) {
      fputs("Invalid loadable segment\n", stderr);
      exit(2);
    }
    memcpy(ram + seg.p_paddr, image + seg.p_offset, seg.p_filesz);
  }
  uint32_t entry = elf->e_entry;
  munmap((void *)image, size);
  close(file);
  return entry;
}

static void record_state(const char *event, int cpu, const uint8_t *ram,
                         uint32_t vmcb, unsigned reason) {
  struct kvm_regs r;
  struct kvm_sregs s;
  uint64_t svm_exit;
  KVM(cpu, KVM_GET_REGS, &r);
  KVM(cpu, KVM_GET_SREGS, &s);
  memcpy(&svm_exit, ram + vmcb + 0x70, sizeof(svm_exit));
  fprintf(stderr,
          "{\"event\":\"%s\",\"reason\":%u,\"rip\":\"%#llx\",\"rax\":\"%#llx\","
          "\"rcx\":\"%#llx\",\"cr0\":\"%#llx\",\"cr3\":\"%#llx\","
          "\"cr4\":\"%#llx\",\"efer\":\"%#llx\",\"vmcb_exit\":\"%#llx\"}\n",
          event, reason, r.rip, r.rax, r.rcx, s.cr0, s.cr3, s.cr4, s.efer,
          (unsigned long long)svm_exit);
}

int main(int argc, char **argv) {
  if (argc != 6)
    return 2;
  uint32_t vmcb = strtoul(argv[2], NULL, 0);
  if (vmcb > RamBytes - 4096)
    return 2;
  uint8_t *ram = mmap(NULL, RamBytes, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (ram == MAP_FAILED)
    fail("map RAM");
  uint32_t entry = load_guest(argv[1], ram);
  int kvm = open("/dev/kvm", O_RDWR);
  if (kvm < 0)
    fail("open /dev/kvm");
  int vm = KVM(kvm, KVM_CREATE_VM, 0);
  KVM(vm, KVM_SET_TSS_ADDR, 0xfffbd000);
  KVM(vm, KVM_CREATE_IRQCHIP, 0);
  struct kvm_userspace_memory_region region = {
      .memory_size = RamBytes, .userspace_addr = (uintptr_t)ram};
  KVM(vm, KVM_SET_USER_MEMORY_REGION, &region);
  int cpu = KVM(vm, KVM_CREATE_VCPU, 0);
  struct kvm_cpuid2 *cpuid = calloc(1, sizeof(*cpuid) +
                                        CpuidEntries * sizeof(struct kvm_cpuid_entry2));
  if (!cpuid)
    fail("allocate CPUID");
  cpuid->nent = CpuidEntries;
  KVM(kvm, KVM_GET_SUPPORTED_CPUID, cpuid);
  KVM(cpu, KVM_SET_CPUID2, cpuid);
  free(cpuid);
  struct kvm_run *run = mmap(NULL, KVM(kvm, KVM_GET_VCPU_MMAP_SIZE, 0),
                             PROT_READ | PROT_WRITE, MAP_SHARED, cpu, 0);
  if (run == MAP_FAILED)
    fail("map vCPU");
  struct kvm_sregs s;
  KVM(cpu, KVM_GET_SREGS, &s);
  s.cr0 = 0x31;
  s.cs = (struct kvm_segment){.limit = UINT32_MAX, .selector = 8, .type = 11,
                              .present = 1, .db = 1, .s = 1, .g = 1};
  s.ss = s.ds = s.es = s.fs = s.gs =
      (struct kvm_segment){.limit = UINT32_MAX, .selector = 16, .type = 3,
                           .present = 1, .db = 1, .s = 1, .g = 1};
  KVM(cpu, KVM_SET_SREGS, &s);
  struct kvm_regs regs = {.rip = entry, .rflags = 2, .rax = 0x2badb002};
  KVM(cpu, KVM_SET_REGS, &regs);
  const char *events[] = {"before_vmrun", "after_vmexit", "before_addr32"};
  struct kvm_guest_debug debug = {.control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_HW_BP};
  for (unsigned i = 0; i < 3; ++i) {
    debug.arch.debugreg[i] = strtoul(argv[3 + i], NULL, 0);
    debug.arch.debugreg[7] |= 1ULL << (2 * i);
  }
  debug.arch.debugreg[7] |= 0x400;
  KVM(cpu, KVM_SET_GUEST_DEBUG, &debug);
  for (;;) {
    KVM(cpu, KVM_RUN, 0);
    if (run->exit_reason == KVM_EXIT_DEBUG) {
      unsigned slot = 0;
      while (slot < 3 && run->debug.arch.pc != debug.arch.debugreg[slot])
        ++slot;
      if (slot == 3)
        break;
      record_state(events[slot], cpu, ram, vmcb, run->exit_reason);
      debug.arch.debugreg[7] &= ~(1ULL << (2 * slot));
      KVM(cpu, KVM_SET_GUEST_DEBUG, &debug);
      continue;
    }
    if (run->exit_reason != KVM_EXIT_IO || run->io.direction != KVM_EXIT_IO_OUT)
      break;
    const uint8_t *bytes = (const uint8_t *)run + run->io.data_offset;
    if (run->io.port == 0xe9 && run->io.size == 1) {
      fwrite(bytes, 1, run->io.count, stdout);
      fflush(stdout);
      continue;
    }
    if (run->io.port == 0xf4 && run->io.size == 4 && run->io.count == 1) {
      uint32_t value;
      memcpy(&value, bytes, sizeof(value));
      record_state("exit_port", cpu, ram, vmcb, run->exit_reason);
      return (value << 1 | 1) & 255;
    }
    break;
  }
  record_state("stopped", cpu, ram, vmcb, run->exit_reason);
  return 1;
}
