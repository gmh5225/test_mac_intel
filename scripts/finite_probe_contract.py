"""Independent, complete finite-probe transcript audit; never execute artifacts.

This checks guest observations. Native status, provenance, immutable artifact
hashes, process retirement and optional lifecycle markers remain separate gates.
"""
from collections import Counter
import hashlib
import json
from pathlib import Path
import re


NAME = 'HvfIntelProbe.FiniteDeadline'
MAX_U64 = (1 << 64) - 1


def require(condition, message):
    if not condition:
        raise ValueError(message)


def fields(line, key, numeric):
    pairs = [part.split('=', 1) for part in line.split()[1:]]
    require(all(len(pair) == 2 for pair in pairs), 'malformed probe fields')
    values = dict(pairs)
    require(len(values) == len(pairs), 'duplicate probe field')
    require(set(values) == {key, *numeric}, 'missing or unexpected probe fields')
    for name in numeric:
        value = values[name]
        require(re.fullmatch(r'[0-9]+', value) is not None, 'non-integer probe field')
        values[name] = int(value)
        require(values[name] <= MAX_U64, 'overflowed probe field')
    return values


def validate_finite_output(log, repetitions, *, executor_reuse=False,
                           preparation_phase='prepare_with_transport'):
    require(type(repetitions) is int and repetitions > 0, 'invalid repetition count')
    require(preparation_phase in ('prepare_with_transport', 'prepare_with_watchdog'),
            'unknown preparation version')
    require(log.endswith('\n'), 'unterminated final transcript line')
    stage, started, completed = 'iteration', 0, 0
    call_index = loop_calls = 0
    slice_ticks = 0
    max_loop_calls = no_progress = stale_mtf = 0
    last_nonce = 0
    budget = begin = end = previous = None
    counts = Counter()
    begin_keys = ('call', 'deadline', 'rip', 'nonce', 'witness')
    end_keys = ('call', 'status', 'mach_before', 'mach_after')
    capture_keys = ('call', 'exec_before', 'exec_after', 'reason_before', 'reason',
                    'rip_before', 'rip', 'rax', 'nonce', 'witness')

    for number, line in enumerate(log.splitlines(), 1):
        try:
            iteration = re.fullmatch(r'Repeating all tests \(iteration ([0-9]+)\) \. \. \.', line)
            run = re.fullmatch(r'\[ RUN      \] (.+)', line)
            ok = re.fullmatch(r'\[       OK \] (.+) \([0-9]+ ms\)', line)
            summary = re.fullmatch(r'\[  PASSED  \] ([0-9]+) tests?\.', line)
            if iteration:
                require(stage == 'iteration' and int(iteration[1]) == completed + 1
                        and completed < repetitions, 'out-of-order iteration')
                started += 1
                stage = 'run'
                call_index = loop_calls = 0
                budget = begin = end = previous = None
                continue
            if run:
                require(stage == 'run' and run[1] == NAME, 'unexpected RUN')
                stage = 'executor_initialization'
                continue
            if ok:
                require(stage == 'ok' and ok[1] == NAME, 'OK without complete finite observations')
                stage = 'summary'
                continue
            if summary:
                require(stage == 'summary' and summary[1] == '1', 'unexpected summary')
                completed += 1
                stage = 'iteration'
                continue
            require(not re.search(r'\[\s*(?:FAILED|SKIPPED)\s*\]|Failure$', line),
                    'native assertion or skip')
            if line.startswith('INTEL_LIFECYCLE'):
                require(stage == 'ok' or (stage == 'iteration' and completed == repetitions),
                        'lifecycle event precedes completed finite body')
                continue  # The separate lifecycle parser verifies every field.
            if not line.startswith('INTEL_PROBE'):
                continue
            if line.startswith('INTEL_PROBE phase='):
                phase = fields(line, 'phase', ())['phase']
                transitions = {
                    'executor_initialization': ('executor_initialization',
                        'executor_retained' if executor_reuse else 'startup_probe'),
                    'executor_retained': ('executor_retained', 'startup_probe'),
                    'startup_probe': ('startup_probe', 'prepare_loop'),
                    'prepare_loop': (preparation_phase, 'budget'),
                    'no_progress_marker': ('finite_slice_without_guest_progress', 'loop_begin'),
                    'prepare_expired': (preparation_phase, 'expired_begin'),
                    'prepare_finite': (preparation_phase, 'finite_begin'),
                    'verified_retry': ('verified_retry', 'prepare_retry'),
                    'prepare_retry': (preparation_phase, 'finite_retirement'),
                    'finite_retirement': ('finite_retirement', 'ok'),
                }
                require(stage in transitions and transitions[stage][0] == phase,
                        'unexpected or missing finite phase')
                stage = transitions[stage][1]
                continue
            if line.startswith('INTEL_PROBE witness_budget '):
                require(stage == 'budget' and budget is None, 'missing or repeated witness budget')
                # The marker has no '=' after witness_budget, unlike event fields.
                budget = fields(line.replace('witness_budget ', 'kind=budget ', 1),
                    'kind', ('mach_start', 'mach_end', 'remaining_ns', 'timebase_numer',
                             'timebase_denom', 'max_calls'))
                require(budget['max_calls'] == 4096 and 0 < budget['remaining_ns'] <= 2000000000
                        and 0 < budget['timebase_numer'] <= 0xffffffff
                        and 0 < budget['timebase_denom'] <= 0xffffffff,
                        'invalid fixed witness budget')
                slice_ticks = 5000000 * budget['timebase_denom'] // budget['timebase_numer']
                require(slice_ticks > 0, 'five millisecond slice rounds to zero')
                require(budget['mach_end'] == budget['mach_start'] +
                        budget['remaining_ns'] * budget['timebase_denom'] // budget['timebase_numer']
                        and budget['mach_end'] > budget['mach_start'], 'inconsistent Mach budget')
                stage = 'loop_begin'
                continue
            if line.startswith('INTEL_PROBE begin='):
                expected = {'loop_begin': 'finite_loop', 'expired_begin': 'expired_mtf',
                            'finite_begin': 'finite_mtf'}
                require(stage in expected, 'missing capture or unexpected call begin')
                current = fields(line, 'begin', begin_keys)
                phase = current['begin']
                require(phase == expected[stage] and current['call'] == call_index + 1,
                        'wrong phase or noncontiguous call number')
                call_index += 1
                require(current['nonce'] > 0, 'zero nonce cannot prove a fresh store')
                if phase == 'finite_loop':
                    loop_calls += 1
                    require(loop_calls <= 4096, 'witness call cap exceeded')
                    require(budget['mach_start'] < current['deadline'] <= budget['mach_end'],
                            'renewed or invalid witness deadline')
                    if loop_calls == 1:
                        require(current['rip'] == 65537 and current['witness'] == 0,
                                'missing fresh store initial state')
                        require(current['nonce'] > last_nonce, 'nonce reused across preparations')
                        require(current['nonce'] < budget['mach_start'], 'witness nonce was not prepared before budget')
                        require(current['deadline'] >= min(budget['mach_end'],
                                budget['mach_start'] + slice_ticks), 'first finite slice is too short')
                        last_nonce = current['nonce']
                    else:
                        require(current['nonce'] == begin['nonce'] and
                                (current['rip'], current['witness']) ==
                                (previous['rip'], previous['witness']), 'loop state changed between calls')
                        if previous['reason'] == 1:
                            require(current['deadline'] == begin['deadline'], 'IRQ renewed finite slice')
                        else:
                            require(current['deadline'] >= min(budget['mach_end'],
                                    previous['_mach_after'] + slice_ticks),
                                    'no-progress timer did not acquire a new bounded slice')
                else:
                    require(current['rip'] == 65543 and current['witness'] == 0,
                            'missing fresh MTF preparation')
                    require(current['nonce'] > last_nonce, 'nonce reused across preparations')
                    require(current['nonce'] >= previous['_mach_after'], 'MTF nonce predates prior call')
                    last_nonce = current['nonce']
                    require((current['deadline'] == 0) == (phase == 'expired_mtf'),
                            'wrong expired/finite deadline')
                    if phase == 'finite_mtf':
                        require(current['deadline'] >= current['nonce'] + slice_ticks,
                                'finite MTF deadline predates the prepared slice')
                begin, end, stage = current, None, 'end'
                continue
            if line.startswith('INTEL_PROBE end='):
                require(stage == 'end', 'missing begin or duplicate call end')
                end = fields(line, 'end', end_keys)
                require(end['end'] == begin['begin'] and end['call'] == begin['call'],
                        'call end does not match begin')
                require(end['status'] == 0 and end['mach_after'] >= end['mach_before'],
                        'native call error or reversed clock')
                require(begin['nonce'] < end['mach_before'], 'nonce does not precede native entry')
                if previous is not None:
                    require(end['mach_before'] >= previous['_mach_after'], 'native call clock moved backward')
                if begin['begin'] != 'expired_mtf':
                    # A descheduled entry may begin after its deadline. Do not
                    # invent an entry guarantee absent from hv_vcpu_run_until.
                    require(begin['deadline'] <= end['mach_before'] + slice_ticks,
                            'finite slice exceeds five milliseconds')
                if begin['begin'] == 'finite_loop':
                    require(end['mach_before'] >= budget['mach_start'], 'call predates witness budget')
                stage = 'capture'
                continue
            if line.startswith('INTEL_PROBE capture='):
                require(stage == 'capture', 'missing end or duplicate capture')
                current = fields(line, 'capture', capture_keys)
                phase = current['capture']
                require(phase == begin['begin'] and current['call'] == begin['call']
                        and current['nonce'] == begin['nonce']
                        and current['rip_before'] == begin['rip'], 'capture identity differs from begin')
                require(current['exec_after'] >= current['exec_before'], 'execution time moved backward')
                if previous is not None:
                    require(current['exec_before'] >= previous['exec_after'], 'vCPU execution time reset within iteration')
                if phase == 'finite_loop':
                    require(current['reason'] in (1, 52) and current['rax'] == current['nonce'],
                            'unexpected finite exit or changed nonce register')
                    require((current['rip'], current['witness']) in
                            ((65537, 0), (65540, current['nonce'])), 'incorrect store witness/RIP pair')
                    if begin['rip'] == 65540:
                        require((current['rip'], current['witness']) == (65540, current['nonce']),
                                'completed store or loop PC moved backward')
                    if loop_calls > 1:
                        require(current['reason_before'] == previous['reason'], 'exit reason changed between raw calls')
                    else:
                        require(current['reason_before'] == 37, 'first loop was not prepared by MTF')
                    if current['reason'] == 52 and current['witness'] == current['nonce']:
                        max_loop_calls = max(max_loop_calls, loop_calls)
                        stage = 'prepare_expired'
                    elif current['reason'] == 52:
                        no_progress += 1
                        stage = 'no_progress_marker'
                    else:
                        stage = 'loop_begin'
                else:
                    require(current['reason_before'] == 37 and current['reason'] in (1, 37, 52),
                            'unexpected MTF observation exit')
                    require(current['witness'] == 0 and (current['rip'], current['rax']) in
                            ((65543, current['nonce']), (65546, (current['nonce'] + 1) & MAX_U64)),
                            'incorrect MTF register observation')
                    # The API may retain an old MTF reason without entering.
                    # Keep that as no progress; it is not a completed INC.
                    stale_mtf += int(current['reason'] == 37 and current['rip'] == 65543)
                    stage = 'prepare_finite' if phase == 'expired_mtf' else 'verified_retry'
                counts[phase, current['reason'], current['rip'] - current['rip_before']] += 1
                current['_mach_after'] = end['mach_after']
                previous = current
                continue
            raise ValueError('unknown or malformed finite probe marker')
        except ValueError as error:
            raise ValueError(f'line {number}, iteration {started}, stage {stage}: {error}') from error
    require(completed == repetitions and started == repetitions and stage == 'iteration',
            'incomplete finite transcript')
    return {'complete_iterations': completed, 'timer_store_witnesses': completed,
            'expired_mtf_observations': completed, 'finite_mtf_observations': completed,
            'all_call_triplets_ordered': True, 'all_fixed_witness_budgets_verified': True,
            'max_calls_in_one_witness': max_loop_calls, 'no_progress_timer_slices': no_progress,
            'stale_mtf_no_entry_observations': stale_mtf,
            'preparation_phase': preparation_phase,
            'captures': [dict(phase=p, reason=r, rip_delta=d, count=n)
                         for (p, r, d), n in sorted(counts.items())]}


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('log', type=Path)
    parser.add_argument('--repetitions', required=True, type=int)
    parser.add_argument('--executor-reuse', action='store_true')
    parser.add_argument('--preparation-phase', default='prepare_with_transport',
                        choices=('prepare_with_transport', 'prepare_with_watchdog'))
    args = parser.parse_args()
    raw = args.log.read_bytes()
    observations = validate_finite_output(raw.decode(), args.repetitions,
        executor_reuse=args.executor_reuse, preparation_phase=args.preparation_phase)
    print(json.dumps({'kind': 'complete-finite-guest-observation-audit', 'schema': 1,
        'output_sha256': hashlib.sha256(raw).hexdigest(),
        'auditor_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'native_exit_verified': False, 'complete_native_acceptance': False,
        **observations}, indent=2))
