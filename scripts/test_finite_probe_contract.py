"""Behavioral counterexamples for the immutable transcript auditor."""
import unittest

from finite_probe_contract import NAME, validate_finite_output


def transcript(iteration=1, *, exits=(52,), stale=False, reuse=False):
    start = iteration * 10000000000
    nonce = start - 100
    output = [f'Repeating all tests (iteration {iteration}) . . .',
              f'[ RUN      ] {NAME}', 'INTEL_PROBE phase=executor_initialization']
    if reuse:
        output.append('INTEL_PROBE phase=executor_retained')
    output += ['INTEL_PROBE phase=startup_probe', 'INTEL_PROBE phase=prepare_with_transport',
               f'INTEL_PROBE witness_budget mach_start={start} mach_end={start + 2000000000} '
               'remaining_ns=2000000000 timebase_numer=1 timebase_denom=1 max_calls=4096']
    now, deadline, rip, witness, reason, elapsed = start + 100, start + 5000000, 65537, 0, 37, 100

    def call(phase, index, call_nonce, call_deadline, old_rip, old_witness, old_reason,
             new_rip, new_witness, new_reason, before, after, exec_before, increment=False):
        return [f'INTEL_PROBE begin={phase} call={index} deadline={call_deadline} '
                f'rip={old_rip} nonce={call_nonce} witness={old_witness}',
                f'INTEL_PROBE end={phase} call={index} status=0 mach_before={before} mach_after={after}',
                f'INTEL_PROBE capture={phase} call={index} exec_before={exec_before} '
                f'exec_after={exec_before + 100} reason_before={old_reason} reason={new_reason} '
                f'rip_before={old_rip} rip={new_rip} rax={call_nonce + int(increment)} '
                f'nonce={call_nonce} witness={new_witness}']

    for index, next_reason in enumerate(exits, 1):
        last = index == len(exits)
        next_rip = 65540 if last or witness else 65537
        next_witness = nonce if next_rip == 65540 else 0
        after = max(now + 100, deadline + 100) if next_reason == 52 else now + 100
        output += call('finite_loop', index, nonce, deadline, rip, witness, reason,
                       next_rip, next_witness, next_reason, now, after, elapsed)
        now, rip, witness, reason, elapsed = after + 100, next_rip, next_witness, next_reason, elapsed + 100
        if next_reason == 52 and not witness:
            output.append('INTEL_PROBE phase=finite_slice_without_guest_progress')
            deadline = now + 5000000
    for phase, is_expired in (('expired_mtf', True), ('finite_mtf', False)):
        index += 1
        nonce = now
        before, after = now + 200, now + 400
        output.append('INTEL_PROBE phase=prepare_with_transport')
        new_rip = 65543 if is_expired else 65546
        new_reason = 37 if stale or not is_expired else 52
        output += call(phase, index, nonce, 0 if is_expired else now + 5000000,
                       65543, 0, 37, new_rip, 0, new_reason, before, after,
                       elapsed + 100, increment=not is_expired)
        now, elapsed = after + 100, elapsed + 200
    output += ['INTEL_PROBE phase=verified_retry', 'INTEL_PROBE phase=prepare_with_transport',
               'INTEL_PROBE phase=finite_retirement', f'[       OK ] {NAME} (12 ms)',
               '[  PASSED  ] 1 test.']
    return '\n'.join(output) + '\n'


class FiniteProbeContractTests(unittest.TestCase):
    def test_fresh_store_and_both_mtf_observations(self):
        result = validate_finite_output(transcript() + transcript(2), 2)
        self.assertEqual(result['timer_store_witnesses'], 2)
        self.assertEqual(result['expired_mtf_observations'], 2)
        self.assertEqual(result['finite_mtf_observations'], 2)

    def test_timer_without_guest_progress_then_irq_then_real_store(self):
        result = validate_finite_output(transcript(exits=(52, 1, 52)), 1)
        self.assertEqual(result['no_progress_timer_slices'], 1)
        self.assertEqual(result['max_calls_in_one_witness'], 3)

    def test_stale_mtf_is_no_entry_not_an_increment(self):
        result = validate_finite_output(transcript(stale=True), 1)
        self.assertEqual(result['stale_mtf_no_entry_observations'], 1)

    def test_retained_executor_requires_its_marker(self):
        validate_finite_output(transcript(reuse=True), 1, executor_reuse=True)
        with self.assertRaises(ValueError):
            validate_finite_output(transcript(), 1, executor_reuse=True)
        with self.assertRaises(ValueError):
            validate_finite_output(transcript(reuse=True), 1)

    def test_legacy_preparation_is_explicit(self):
        log = transcript().replace('prepare_with_transport', 'prepare_with_watchdog')
        with self.assertRaises(ValueError):
            validate_finite_output(log, 1)
        validate_finite_output(log, 1, preparation_phase='prepare_with_watchdog')

    def test_missing_duplicate_or_swapped_event_cannot_use_gtest_totals(self):
        lines = transcript().splitlines()
        indices = [i for i, line in enumerate(lines) if line.startswith('INTEL_PROBE')]
        for index in indices:
            with self.subTest(index=index, mutation='missing'):
                with self.assertRaises(ValueError):
                    validate_finite_output('\n'.join(lines[:index] + lines[index+1:]) + '\n', 1)
            with self.subTest(index=index, mutation='duplicate'):
                with self.assertRaises(ValueError):
                    validate_finite_output('\n'.join(lines[:index] + [lines[index]] + lines[index:]) + '\n', 1)
        index = next(i for i, line in enumerate(lines) if line.startswith('INTEL_PROBE begin='))
        lines[index], lines[index+1] = lines[index+1], lines[index]
        with self.assertRaises(ValueError):
            validate_finite_output('\n'.join(lines) + '\n', 1)

    def test_wrong_call_identity(self):
        mutations = (('end=finite_loop call=1', 'end=finite_loop call=2'),
                     ('capture=finite_loop call=1', 'capture=finite_loop call=2'),
                     ('begin=expired_mtf call=2', 'begin=expired_mtf call=3'),
                     ('end=finite_loop', 'end=expired_mtf'))
        for old, new in mutations:
            with self.subTest(mutation=new), self.assertRaises(ValueError):
                validate_finite_output(transcript().replace(old, new, 1), 1)

    def test_bad_register_witness_pairs_and_native_errors(self):
        mutations = (('status=0', 'status=1'), ('reason=52', 'reason=48'),
                     ('rip=65540 rax=', 'rip=65537 rax='),
                     ('rip=65546 rax=10005000901', 'rip=65543 rax=10005000901'),
                     ('nonce=9999999900 witness=9999999900', 'nonce=9999999900 witness=0'),
                     ('rax=9999999900', 'rax=9999999901'),
                     ('rip_before=65537', 'rip_before=65540'),
                     ('exec_after=200', 'exec_after=99'),
                     ('reason_before=37 reason=52', 'reason_before=1 reason=52'))
        for old, new in mutations:
            original = transcript()
            # Make a stale PC paired with the incremented value directly from
            # the final capture rather than relying on wall-clock literals.
            if old.startswith('rip=65546'):
                changed = original.replace('rip=65546 rax=', 'rip=65543 rax=', 1)
            else:
                self.assertIn(old, original)
                changed = original.replace(old, new, 1)
            with self.subTest(mutation=new), self.assertRaises(ValueError):
                validate_finite_output(changed, 1)

    def test_budget_cannot_be_renewed_or_forged(self):
        mutations = (('remaining_ns=2000000000', 'remaining_ns=2000000001'),
                     ('mach_end=12000000000', 'mach_end=12000000001'),
                     ('max_calls=4096', 'max_calls=4097'),
                     ('timebase_numer=1', 'timebase_numer=0'),
                     ('timebase_numer=1', 'timebase_numer=4294967296'),
                     ('timebase_denom=1', 'timebase_denom=4294967296'),
                     ('deadline=10005000000', 'deadline=13000000000'),
                     ('deadline=10005000000', 'deadline=10000000001'),
                     ('deadline=0', 'deadline=1'))
        for old, new in mutations:
            with self.subTest(mutation=new), self.assertRaises(ValueError):
                validate_finite_output(transcript().replace(old, new, 1), 1)

    def test_finite_mtf_cannot_use_an_expired_deadline(self):
        import re
        log = re.sub(r'(begin=finite_mtf call=3 deadline=)[0-9]+', r'\g<1>1', transcript())
        with self.assertRaises(ValueError):
            validate_finite_output(log, 1)

    def test_empty_timer_slice_cannot_reuse_its_expired_deadline(self):
        import re
        log = transcript(exits=(52, 52))
        changed = re.sub(r'(begin=finite_loop call=2 deadline=)[0-9]+', r'\g<1>10005000000', log)
        self.assertNotEqual(changed, log)
        with self.assertRaises(ValueError):
            validate_finite_output(changed, 1)

    def test_witness_call_cap_allows_two_later_mtf_calls(self):
        result = validate_finite_output(transcript(exits=(1,) * 4095 + (52,)), 1)
        self.assertEqual(result['max_calls_in_one_witness'], 4096)
        with self.assertRaises(ValueError):
            validate_finite_output(transcript(exits=(1,) * 4096 + (52,)), 1)

    def test_later_mtf_calls_have_separate_controls(self):
        import re
        lines = transcript().splitlines()
        for i, line in enumerate(lines):
            if re.match(r'INTEL_PROBE (?:begin|end|capture)=(?:expired_mtf|finite_mtf)', line):
                lines[i] = re.sub(r'((?:nonce|rax|deadline|mach_before|mach_after)=)([0-9]+)',
                    lambda m: m[1] + str(int(m[2]) + (3000000000 if int(m[2]) else 0)), line)
        validate_finite_output('\n'.join(lines) + '\n', 1)

    def test_only_irq_never_proves_timer_store(self):
        with self.assertRaises(ValueError):
            validate_finite_output(transcript(exits=(1,)), 1)

    def test_irq_cannot_renew_deadline(self):
        log = transcript(exits=(1, 52))
        old = 'begin=finite_loop call=2 deadline=10005000000'
        self.assertIn(old, log)
        with self.assertRaises(ValueError):
            validate_finite_output(log.replace(old, 'begin=finite_loop call=2 deadline=10005000001'), 1)

    def test_cross_iteration_transcript_replay_does_not_supply_fresh_nonce(self):
        second = transcript().replace('iteration 1', 'iteration 2')
        with self.assertRaises(ValueError):
            validate_finite_output(transcript() + second, 2)

    def test_malformed_duplicate_and_unknown_probe_fields(self):
        for old, new in (('call=1 deadline=', 'call=1 call=1 deadline='),
                         ('call=1 deadline=', 'call=1 ignored=1 deadline='),
                         ('call=1 deadline=', 'call=-1 deadline='),
                         ('phase=verified_retry', 'phase=verified_retry extra'),
                         ('phase=verified_retry', 'phase=unrecognized'),
                         ('deadline=0', 'deadline=18446744073709551616')):
            with self.subTest(mutation=new), self.assertRaises(ValueError):
                validate_finite_output(transcript().replace(old, new, 1), 1)

    def test_incomplete_or_failed_native_transcript_is_not_a_pass(self):
        for log in (transcript().rstrip('\n'), transcript().split('INTEL_PROBE end=')[0],
                    transcript().replace('[       OK ]', '[  FAILED  ]'),
                    transcript().replace('[       OK ]', '[  SKIPPED ]')):
            with self.subTest(log=log[-80:]), self.assertRaises(ValueError):
                validate_finite_output(log, 1)

    def test_lifecycle_cannot_move_before_finite_body_finishes(self):
        marker = 'INTEL_LIFECYCLE phase=vcpu_destroy_begin generation=1 owner=42\n'
        log = transcript().replace('INTEL_PROBE phase=verified_retry\n',
                                   marker + 'INTEL_PROBE phase=verified_retry\n')
        with self.assertRaises(ValueError):
            validate_finite_output(log, 1)


if __name__ == '__main__':
    unittest.main()
