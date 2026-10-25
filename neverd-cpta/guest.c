//===- guest.c - CPA2 capability and EL1 execution controls -------------===//
//
// NeverD Decompiler
//
//===----------------------------------------------------------------------===//

#include "CptaGuest.def"

#include <stddef.h>
#include <stdint.h>

static unsigned Passed, Failed;

static void writeText(const char *Text) {
  register uint64_t Operation __asm__(CPA_OPERATION_REGISTER) =
      CPA_SEMIHOST_WRITE0;
  register const char *Parameter __asm__(CPA_PARAMETER_REGISTER) = Text;
  __asm__ volatile(CPA_SEMIHOST_TRAP
                   : CPA_REGISTER_INOUT(Operation)
                   : CPA_REGISTER_INPUT(Parameter)
                   : CPA_MEMORY_CLOBBER);
}

static void record(const char *Name, uint64_t Value) {
  char Digits[sizeof(Value) * 2 + 1];
  for (size_t I = 0; I < sizeof(Value) * 2; ++I)
    Digits[I] = CPA_HEX_DIGITS[(Value >> ((sizeof(Value) * 2 - I - 1) * 4)) &
                               CPA_EL_FIELD_MASK];
  Digits[sizeof(Value) * 2] = 0;
  writeText(CPA_ROW_PREFIX);
  writeText(Name);
  writeText(CPA_ROW_VALUE);
  writeText(Digits);
  writeText(CPA_ROW_END);
}

static void expect(int Condition) {
  if (Condition)
    ++Passed;
  else
    record(CPA_FAILURE_INDEX_NAME, Passed + ++Failed);
}

extern const unsigned char GuestDataStart[];
_Alignas(CPA_PAGE_BYTES) static uint64_t NormalRoot[CPA_TABLE_ENTRIES];
_Alignas(CPA_PAGE_BYTES) static uint64_t NormalL2[CPA_TABLE_ENTRIES];
_Alignas(CPA_PAGE_BYTES) static uint64_t NormalL3[CPA_TABLE_ENTRIES];

static void configureNormalMemory(void) {
  NormalRoot[CPA_ROOT_INDEX] = (uint64_t)NormalL2 | CPA_TABLE_DESCRIPTOR;
  NormalL2[CPA_L2_INDEX] = (uint64_t)NormalL3 | CPA_TABLE_DESCRIPTOR;
  for (unsigned I = 0; I != CPA_TABLE_ENTRIES; ++I) {
    const uint64_t Address = CPA_GUEST_BASE + (uint64_t)I * CPA_PAGE_BYTES;
    NormalL3[I] =
        Address |
        (Address < (uint64_t)GuestDataStart ? CPA_CODE_PAGE : CPA_DATA_PAGE);
  }
  const uint64_t MAIR = CPA_NORMAL_MAIR;
  const uint64_t TCR = CPA_NORMAL_TCR;
  const uint64_t TTBR = (uint64_t)NormalRoot;
  __asm__ volatile(CPA_CONFIGURE_TRANSLATION
                   :
                   : CPA_REGISTER_INPUT(MAIR), CPA_REGISTER_INPUT(TCR),
                     CPA_REGISTER_INPUT(TTBR)
                   : CPA_MEMORY_CLOBBER);
  uint64_t SCTLR, Observed;
  __asm__ volatile(CPA_READ_SCTLR : CPA_REGISTER_OUTPUT(SCTLR));
  SCTLR = (SCTLR & ~CPA_MEMORY_SCTLR_CLEAR) | CPA_MEMORY_SCTLR_SET;
  __asm__ volatile(CPA_WRITE_SCTLR
                   :
                   : CPA_REGISTER_INPUT(SCTLR)
                   : CPA_MEMORY_CLOBBER);
  __asm__ volatile(CPA_READ_MAIR : CPA_REGISTER_OUTPUT(Observed));
  record(CPA_NORMAL_MAIR_NAME, Observed);
  expect(Observed == MAIR);
  __asm__ volatile(CPA_READ_TCR : CPA_REGISTER_OUTPUT(Observed));
  record(CPA_NORMAL_TCR_NAME, Observed);
  expect(Observed == TCR);
  __asm__ volatile(CPA_READ_TTBR : CPA_REGISTER_OUTPUT(Observed));
  record(CPA_NORMAL_TTBR_NAME, Observed == TTBR);
  expect(Observed == TTBR);
  __asm__ volatile(CPA_READ_SCTLR : CPA_REGISTER_OUTPUT(Observed));
  record(CPA_NORMAL_SCTLR_NAME, Observed & CPA_MEMORY_SCTLR_MASK);
  expect((Observed & CPA_MEMORY_SCTLR_MASK) == CPA_MEMORY_SCTLR_SET);
  __asm__ volatile(CPA_READ_PAN : CPA_REGISTER_OUTPUT(Observed));
  record(CPA_NORMAL_PAN_NAME, Observed);
  expect(Observed == 0);
  __asm__ volatile(CPA_READ_UAO : CPA_REGISTER_OUTPUT(Observed));
  record(CPA_NORMAL_UAO_NAME, Observed);
  expect(Observed == 0);
}

void reportUnexpected(uint64_t ESR, uint64_t ELR, uint64_t FAR,
                      uint64_t Stack) {
  record(CPA_UNEXPECTED_ESR_NAME, ESR);
  record(CPA_UNEXPECTED_ELR_NAME, ELR);
  record(CPA_UNEXPECTED_FAR_NAME, FAR);
  record(CPA_UNEXPECTED_SP_NAME, Stack);
}

__attribute__((noreturn)) static void finish(void) {
  record(CPA_TESTS_NAME, Passed);
  record(CPA_FAILURES_NAME, Failed);
  record(CPA_COMPLETE_NAME, 1);
  uint64_t Parameters[] = {CPA_SEMIHOST_APPLICATION_EXIT, Failed != 0};
  register uint64_t Operation __asm__(CPA_OPERATION_REGISTER) =
      CPA_SEMIHOST_EXIT_EXTENDED;
  register uint64_t *Parameter __asm__(CPA_PARAMETER_REGISTER) = Parameters;
  __asm__ volatile(CPA_SEMIHOST_TRAP
                   : CPA_REGISTER_INOUT(Operation)
                   : CPA_REGISTER_INPUT(Parameter)
                   : CPA_MEMORY_CLOBBER);
  for (;;)
    __asm__ volatile(CPA_WAIT);
}

extern uint64_t probeStack(uint64_t Address, uint64_t UseSP);
extern void copyVector(const void *Source, void *Destination, uint64_t Offset);

#if defined(CPA_GENERATED_MEMORY)
extern int CPA_GENERATED_ENTRY(void);
extern unsigned CPA_GENERATED_SAMPLES(void);
#endif

static const struct {
  uint64_t Bits;
  const char *ControlName;
  const char *MemoryName;
  const char *StackAlignmentName;
} Controls[] = {
#define CPA_CONTROL_CASE(Bits, ControlName, MemoryName, AlignmentName)         \
  {Bits, ControlName, MemoryName, AlignmentName},
#include "CptaGuest.def"
};

void guestMain(void) {
  uint64_t EL, PFR, ISAR;
  __asm__ volatile(CPA_READ_EL : CPA_REGISTER_OUTPUT(EL));
  __asm__ volatile(CPA_READ_PFR : CPA_REGISTER_OUTPUT(PFR));
  __asm__ volatile(CPA_READ_ISAR3 : CPA_REGISTER_OUTPUT(ISAR));
  record(CPA_EL_NAME, EL);
  record(CPA_PFR_NAME, PFR);
  record(CPA_ISAR_NAME, ISAR);
  expect(EL == CPA_EL1);
  expect(((PFR >> CPA_EL2_SHIFT) & CPA_EL_FIELD_MASK) == 0);
  expect(((PFR >> CPA_EL3_SHIFT) & CPA_EL_FIELD_MASK) == 0);
  expect((ISAR & CPA_EL_FIELD_MASK) == CPA_FEATURE_LEVEL);
  if (Failed)
    finish();

  configureNormalMemory();
  if (Failed)
    finish();
#if defined(CPA_GENERATED_MEMORY)
  const unsigned Samples = CPA_GENERATED_SAMPLES();
  record(CPA_GENERATED_SAMPLES_NAME, Samples);
  expect(Samples == CPA_GENERATED_SAMPLE_COUNT);
  if (Failed)
    finish();
#endif
  const uint64_t FP = CPA_FP_ENABLE;
  __asm__ volatile(CPA_WRITE_CPACR
                   :
                   : CPA_REGISTER_INPUT(FP)
                   : CPA_MEMORY_CLOBBER);
  for (unsigned Mode = 0; Mode != sizeof(Controls) / sizeof(*Controls);
       ++Mode) {
    const uint64_t Control = Controls[Mode].Bits;
    const int Enabled = (Control & CPA_CPTA) != 0;
    uint64_t Observed;
    __asm__ volatile(CPA_WRITE_SCTLR2
                     :
                     : CPA_REGISTER_INPUT(Control)
                     : CPA_MEMORY_CLOBBER);
    __asm__ volatile(CPA_READ_SCTLR2 : CPA_REGISTER_OUTPUT(Observed));
    record(Controls[Mode].ControlName, Observed);
    expect(Observed == Control);
#define CPA_ARITHMETIC_CASE(Base, Offset, Unchecked, Checked)                  \
  do {                                                                         \
    register uint64_t Result __asm__(CPA_RESULT_REGISTER);                     \
    register uint64_t B __asm__(CPA_BASE_REGISTER) = Base;                     \
    register uint64_t O __asm__(CPA_OFFSET_REGISTER) = (uint64_t)(Offset);     \
    __asm__ volatile(CPA_ADDPT                                                 \
                     : CPA_REGISTER_OUTPUT(Result)                             \
                     : CPA_REGISTER_INPUT(B), CPA_REGISTER_INPUT(O));          \
    expect(Result == (Enabled ? Checked : Unchecked));                         \
  } while (0);
#include "CptaGuest.def"

    _Alignas(CPA_SP_ALIGNMENT)
        uint64_t Source[CPA_MEMORY_BYTES / sizeof(uint64_t)];
    _Alignas(CPA_SP_ALIGNMENT)
        uint64_t Destination[CPA_MEMORY_BYTES / sizeof(uint64_t)];
    for (size_t I = 0; I != sizeof(Source) / sizeof(*Source); ++I) {
      Source[I] = CPA_MEMORY_PATTERN + I;
      Destination[I] = 0;
    }
    uint64_t Loaded;
    const uint64_t Offset = sizeof(uint64_t);
    __asm__ volatile(CPA_LOAD_GPR
                     : CPA_REGISTER_OUTPUT(Loaded)
                     : CPA_REGISTER_INPUT(Source), CPA_REGISTER_INPUT(Offset)
                     : CPA_MEMORY_CLOBBER);
    expect(Loaded == Source[1]);
    copyVector(Source, Destination, 0);
    expect(Destination[0] == Source[0] && Destination[1] == Source[1]);
    expect(Destination[2] == 0 && Destination[3] == 0);

    uint64_t SavedSCTLR;
    __asm__ volatile(CPA_READ_SCTLR : CPA_REGISTER_OUTPUT(SavedSCTLR));
    for (unsigned AlignCheck = 0; AlignCheck != 2; ++AlignCheck) {
      const uint64_t SCTLR =
          AlignCheck ? SavedSCTLR | CPA_SA : SavedSCTLR & ~CPA_SA;
      __asm__ volatile(CPA_WRITE_SCTLR
                       :
                       : CPA_REGISTER_INPUT(SCTLR)
                       : CPA_MEMORY_CLOBBER);
      for (unsigned UseSP = 0; UseSP != 2; ++UseSP)
        for (unsigned Misaligned = 0; Misaligned != 2; ++Misaligned) {
          // Eight-byte alignment satisfies the load while violating SP's
          // sixteen-byte check. The same address in X0 is the control.
          const uint64_t Address =
              (uint64_t)Source + Misaligned * sizeof(uint64_t);
          const uint64_t ESR = probeStack(Address, UseSP);
          expect(AlignCheck && UseSP && Misaligned
                     ? ESR >> CPA_ESR_EC_SHIFT == CPA_SP_ALIGNMENT_EC
                     : ESR == 0);
        }
    }
    __asm__ volatile(CPA_WRITE_SCTLR
                     :
                     : CPA_REGISTER_INPUT(SavedSCTLR)
                     : CPA_MEMORY_CLOBBER);
#if defined(CPA_GENERATED_MEMORY)
#if defined(CPA_GENERATED_STACK_MEMORY)
    const uint64_t StackSCTLR = SavedSCTLR | CPA_SA;
    __asm__ volatile(CPA_WRITE_SCTLR
                     :
                     : CPA_REGISTER_INPUT(StackSCTLR)
                     : CPA_MEMORY_CLOBBER);
    __asm__ volatile(CPA_READ_SCTLR : CPA_REGISTER_OUTPUT(Observed));
    record(Controls[Mode].StackAlignmentName, Observed & CPA_SA);
    expect((Observed & CPA_SA) == CPA_SA);
#endif
    const unsigned MemoryResult = CPA_GENERATED_ENTRY();
    record(Controls[Mode].MemoryName, MemoryResult);
    expect(MemoryResult == 0);
#if defined(CPA_GENERATED_STACK_MEMORY)
    __asm__ volatile(CPA_WRITE_SCTLR
                     :
                     : CPA_REGISTER_INPUT(SavedSCTLR)
                     : CPA_MEMORY_CLOBBER);
#endif
#endif
  }
  finish();
}
