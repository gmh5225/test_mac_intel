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
                   : "+r"(Operation)
                   : "r"(Parameter)
                   : "memory");
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

__attribute__((noreturn)) static void finish(void) {
  record(CPA_TESTS_NAME, Passed);
  record(CPA_FAILURES_NAME, Failed);
  record(CPA_COMPLETE_NAME, 1);
  uint64_t Parameters[] = {CPA_SEMIHOST_APPLICATION_EXIT, Failed != 0};
  register uint64_t Operation __asm__(CPA_OPERATION_REGISTER) =
      CPA_SEMIHOST_EXIT_EXTENDED;
  register uint64_t *Parameter __asm__(CPA_PARAMETER_REGISTER) = Parameters;
  __asm__ volatile(CPA_SEMIHOST_TRAP
                   : "+r"(Operation)
                   : "r"(Parameter)
                   : "memory");
  for (;;)
    __asm__ volatile(CPA_WAIT);
}

extern uint64_t probeStack(uint64_t Address, uint64_t UseSP);
extern void copyVector(const void *Source, void *Destination, uint64_t Offset);

void guestMain(void) {
  uint64_t EL, PFR, ISAR;
  __asm__ volatile(CPA_READ_EL : "=r"(EL));
  __asm__ volatile(CPA_READ_PFR : "=r"(PFR));
  __asm__ volatile(CPA_READ_ISAR3 : "=r"(ISAR));
  record(CPA_EL_NAME, EL);
  record(CPA_PFR_NAME, PFR);
  record(CPA_ISAR_NAME, ISAR);
  expect(EL == CPA_EL1);
  expect(((PFR >> CPA_EL2_SHIFT) & CPA_EL_FIELD_MASK) == 0);
  expect(((PFR >> CPA_EL3_SHIFT) & CPA_EL_FIELD_MASK) == 0);
  expect((ISAR & CPA_EL_FIELD_MASK) == CPA_FEATURE_LEVEL);
  if (Failed)
    finish();

  const uint64_t FP = CPA_FP_ENABLE;
  __asm__ volatile(CPA_WRITE_CPACR : : "r"(FP) : "memory");
  for (unsigned Enabled = 0; Enabled != 2; ++Enabled) {
    const uint64_t Control = Enabled ? CPA_CPTA : 0;
    uint64_t Observed;
    __asm__ volatile(CPA_WRITE_SCTLR2 : : "r"(Control) : "memory");
    __asm__ volatile(CPA_READ_SCTLR2 : "=r"(Observed));
    record(Enabled ? CPA_SCTLR_ON_NAME : CPA_SCTLR_OFF_NAME, Observed);
    expect(Observed == Control);
#define CPA_ARITHMETIC_CASE(Base, Offset, Unchecked, Checked)                  \
  do {                                                                         \
    register uint64_t Result __asm__(CPA_RESULT_REGISTER);                     \
    register uint64_t B __asm__(CPA_BASE_REGISTER) = Base;                     \
    register uint64_t O __asm__(CPA_OFFSET_REGISTER) = (uint64_t)(Offset);     \
    __asm__ volatile(CPA_ADDPT : "=r"(Result) : "r"(B), "r"(O));               \
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
                     : "=r"(Loaded)
                     : "r"(Source), "r"(Offset)
                     : "memory");
    expect(Loaded == Source[1]);
    copyVector(Source, Destination, 0);
    expect(Destination[0] == Source[0] && Destination[1] == Source[1]);
    expect(Destination[2] == 0 && Destination[3] == 0);

    uint64_t SavedSCTLR;
    __asm__ volatile(CPA_READ_SCTLR : "=r"(SavedSCTLR));
    for (unsigned AlignCheck = 0; AlignCheck != 2; ++AlignCheck) {
      const uint64_t SCTLR =
          AlignCheck ? SavedSCTLR | CPA_SA : SavedSCTLR & ~CPA_SA;
      __asm__ volatile(CPA_WRITE_SCTLR : : "r"(SCTLR) : "memory");
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
    __asm__ volatile(CPA_WRITE_SCTLR : : "r"(SavedSCTLR) : "memory");
  }
  finish();
}
