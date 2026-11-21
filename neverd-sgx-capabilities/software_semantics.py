#!/usr/bin/env python3
"""Run the hosted Linux x64 software owners and retain each execution result."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET

MODE = "X86ModeInterruptTest."
TESTS = {
    "NeverDX86PagingTests": [
        "X86PagingTest.EnclavePrivatePagesEnforcePagingIdentityAndEpcmPermissions",
    ],
    "NeverDX64PagedExecutionTests": [
        MODE + "TaskGateAndNestedIretPublishBothTaskBanks",
        MODE + "PartiallyLoadedIncomingTaskResumesTheOriginalTransfer",
        MODE + "VM86InterruptAndReturnUseEveryFrameSelector",
        MODE + "CompatibilityReturnsSelectTheDestinationCodeWidth",
        "X86ModeExecutionTest.CompiledFastCallReturnsToTheOriginalCompatibilityStream",
        "X86ModeExecutionTest.FarTransfersRetireTheirContinuationAfterDescriptorRepair",
        "X86ModeFastSystemTest.TransfersUseFullMsrsAndSelectDestinationWidth",
        "X86ModeFastSystemTest.SysenterMsrsUseProcessorAddressWidthBeforeTransfer",
        "X86ModeFastSystemTest.FaultsPrecedeFastTransferStateWrites",
        "X86ModeFastSystemTest.SingleStepUsesTheRetiredFullAddressAndStack",
        "X86ModeFastSystemTest.VM86EnterAndRealAddressFaultUseTheirOriginalModes",
        MODE + "SmiUsesPrivateRAMAndRsmHonorsFirmwareEdits",
        MODE + "RsmRestoresNormalizedDebugStateAndRejectsInvalidControlsBeforePaeReload",
        MODE + "RsmDebugUsesFirmwareBeforeCommitAndRestoredTablesAfterCommit",
        MODE + "InactiveRsmDeliversOriginalUndefinedOpcode",
        MODE + "AuthenticatedCr8WriteSynchronizesTprBeforeTheNextEvent",
        MODE + "MachineCheckReportsRetainBankOwnershipAndPriority",
        MODE + "MachineCheckMsrReadAndAcknowledgeUseOriginalInstructions",
        MODE + "CorrectedErrorsCountToCmciAndKeepMaskedArrivals",
        MODE + "CmciNmiAndSmiUseTheExistingEventLatches",
        MODE + "StartupInputsRequireBindingAndRestartShutdown",
        MODE + "StartupInitStaysLatchedInSmmUntilRsmCompletes",
        "X86ModeSgxThreadTest.EnclaveNotificationResumeAndDecrementSelectCorrectFrames",
        "X86ModeSgxThreadTest.DebugOptInSelectsTrapAndBreakpointState",
        "X86ModeSgxThreadTest.NestedHandlerRepairsDivideAtOriginalInstruction",
        "X86ModeSgxTest.SoftwareEnclaveResumesFromSSAAfterIRQAndInstructionFaults",
    ],
}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "build", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    compiler = os.environ["NEVERD_TEST_NEVERC"]
    revision = subprocess.check_output(["git", "-C", args.source, "rev-parse", "HEAD"], text=True).strip()
    report = {"source_commit": revision, "neverc_version": subprocess.check_output(
        [compiler, "--version"], text=True).strip(), "cases": []}
    failed = False
    for binary, names in TESTS.items():
        xml = output / (binary + ".xml")
        log = output / (binary + ".log")
        command = [args.build.resolve() / "bin" / binary, "--gtest_filter=" + ":".join(names),
                   "--gtest_output=xml:" + str(xml)]
        with log.open("w") as stream:
            code = subprocess.run(command, cwd=args.source, stdout=stream,
                                  stderr=subprocess.STDOUT).returncode
        print(log.read_text(errors="replace"), flush=True)
        seen = set()
        if xml.is_file():
            for case in ET.parse(xml).iter("testcase"):
                name = case.get("classname") + "." + case.get("name")
                status = "failed" if case.find("failure") is not None else (
                    "skipped" if case.find("skipped") is not None else "passed")
                report["cases"].append({"name": name, "status": status})
                failed |= status != "passed" or name in seen
                seen.add(name)
        failed |= bool(code) or seen != set(names)
        if seen != set(names):
            print("Missing cases:", sorted(set(names) - seen), flush=True)
    report["passed"] = sum(case["status"] == "passed" for case in report["cases"])
    report["expected"] = sum(map(len, TESTS.values()))
    (output / "software.json").write_text(json.dumps(report, indent=2) + "\n")
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(summary, "a") as stream:
            stream.write(f"NeverD software semantics at `{revision}`: "
                         f"**{report['passed']}/{report['expected']} passed**.\n")
    return int(failed)

if __name__ == "__main__":
    raise SystemExit(main())
