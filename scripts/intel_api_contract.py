"""Independent, fail-closed audit of the real-mode finite HVF JSONL protocol."""
import hashlib
import json

SLICE_NS = 5_000_000
BUDGET_NS = 2_000_000_000
CALL_LIMIT = 4096
EVENT_LIMIT = 65536
# Architectural VMCS encodings from Apple's hv_arch_vmx.h / Intel SDM.
CONTROLS = [(0x4000, 9, 0), (0x4002, (1 << 31) | (1 << 7), (1 << 27) | (1 << 21)),
            (0x401e, (1 << 1) | (1 << 7), 0), (0x4012, 1 << 15, 1 << 9)]
STATE_FIELDS = [[0x4004, 0xffffffff], [0x4006, 0], [0x4008, 0], [0x4016, 0],
                [0x6000, 0x60000000], [0x6004, 0], [0x6002, 0], [0x6006, 0],
                [0x400a, 0], [0x401c, 0], [0x4826, 0], [0x4824, 0], [0x6822, 0],
                [0x681a, 0x400], [0x2806, 0], [0x6802, 0], [0x6816, 0], [0x4810, 0],
                [0x6818, 0], [0x4812, 0], [0x80c, 0], [0x6812, 0], [0x480c, 0],
                [0x4820, 0x10000], [0x80e, 0], [0x6814, 0], [0x480e, 0], [0x4822, 0x83]]
for _n in range(6):
    STATE_FIELDS += [[0x800 + 2*_n, 0], [0x6806 + 2*_n, 0],
                     [0x4800 + 2*_n, 0xffff], [0x4814 + 2*_n, 0x9b if _n == 1 else 0x93]]
STATE_FIELDS += [[0x681e, 0x100], [0x6820, 2]]
COMMON = {'event', 'seq', 'iteration', 'owner', 'vm_generation', 'cpu_generation'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def _object(items):
    result = {}
    for key, value in items:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def _same(actual, expected):
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(_same(a, b) for a, b in zip(actual, expected))
    return actual == expected


def records(raw):
    require(len(raw) <= 32*1024*1024, 'output exceeds byte limit')
    require(raw.endswith(b'\n'), 'unterminated output')
    result = []
    # JSONL is LF-delimited. CR/CRCR before LF are JSON whitespace, not
    # additional records; real blank LF records remain invalid JSON.
    for line in raw.split(b'\n')[:-1]:
        item = json.loads(line, object_pairs_hook=_object,
                          parse_float=lambda value: (_ for _ in ()).throw(ValueError(value)),
                          parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
        require(isinstance(item, dict), 'expected event object')
        for key in COMMON - {'event'}:
            require(type(item.get(key)) is int and 0 <= item[key] < 2**64, 'invalid common integer')
        result.append(item)
    require(0 < len(result) <= EVENT_LIMIT, 'empty or excessive output')
    return result


class Reader:
    def __init__(self, values):
        self.values = values
        self.index = self.iteration = self.vm = self.cpu = 0
        self.owner = values[0]['owner']
        require(self.owner > 0, 'invalid owner')

    def take(self, kind, **expected):
        require(self.index < len(self.values), 'missing ' + kind)
        item = self.values[self.index]
        self.index += 1
        require(set(item) == COMMON | set(expected), 'unexpected fields: ' + kind)
        require(item['event'] == kind and item['seq'] == self.index, 'event order: ' + kind)
        require(item['iteration'] == self.iteration and item['owner'] == self.owner, 'iteration/owner')
        require(item['vm_generation'] == self.vm and item['cpu_generation'] == self.cpu, 'generation')
        for key, value in expected.items():
            if value is not None:
                require(_same(item[key], value), 'mismatch: ' + key)
            elif key != 'fields':
                require(type(item[key]) is int and 0 <= item[key] < 2**64, 'invalid integer: ' + key)
        return item

    def resource(self, operation):
        self.take('resource', operation=operation, phase='begin')
        if operation == 'vm_create':
            self.vm += 1
        if operation == 'cpu_create':
            self.cpu += 1
        self.take('resource', operation=operation, phase='end', status=0)


def audit(raw, mode, iterations=1000):
    require(mode in ('vcpu', 'vm'), 'invalid mode')
    require(type(iterations) is int and 1 <= iterations <= 1000, 'invalid audit iteration count')
    reader = Reader(records(raw))
    program = reader.take('program', version=2, mode=mode, iterations=iterations, memory_bytes=65536,
        guest_hex='a30002ebfe', timebase_numer=None, timebase_denom=None,
        slice_ns=SLICE_NS, budget_ns=BUDGET_NS, call_limit=CALL_LIMIT, event_limit=EVENT_LIMIT)
    numer, denom = program['timebase_numer'], program['timebase_denom']
    require(0 < numer < 2**32 and 0 < denom < 2**32, 'invalid timebase')
    slice_ticks = (SLICE_NS * denom + numer - 1) // numer
    budget_ticks = (BUDGET_NS * denom + numer - 1) // numer
    require(0 < slice_ticks <= budget_ticks < 2**64, 'invalid tick durations')
    if mode == 'vcpu':
        reader.resource('vm_create')
    calls = empty_slices = irqs = 0
    last_capture = 0
    max_calls = 0
    for nonce in range(1, iterations + 1):
        reader.iteration = nonce
        reader.take('iteration_begin', nonce=nonce)
        if mode == 'vm':
            reader.resource('vm_create')
        reader.resource('map')
        reader.resource('cpu_create')
        reader.take('reset', value=0)
        for field, required, forbidden in CONTROLS:
            control = reader.take('control', field=field, required=required, forbidden=forbidden,
                must=None, may=None, effective=None, observed=None)
            must, may = control['must'], control['may']
            require(not must & ~may and not required & ~may and not must & forbidden, 'unsupported control')
            require(control['effective'] == control['observed'] == (must | required), 'control readback')
        registers = []
        for field, requested, forbidden in [(0x6800, 0x20, 0x80000001), (0x6804, 0x2000, 0x20)]:
            control = reader.take('control_register', field=field, requested=requested, forbidden=forbidden,
                must=None, may=None, fixed=None, allowed=None, effective=None, observed=None)
            fixed = control['fixed'] if field == 0x6804 else control['fixed'] & ~0x80000001
            effective = requested | control['must'] | fixed
            require(not control['must'] & ~control['may'], 'invalid register capabilities')
            require(not effective & ~(control['may'] & control['allowed']) and not effective & forbidden,
                    'unsupported register')
            require(control['effective'] == control['observed'] == effective, 'register readback')
            registers.append(effective)
        reader.take('state', nonce=nonce, cr0=registers[0], cr4=registers[1], zero_other_gprs=True, fields=STATE_FIELDS)
        budget = reader.take('budget', start=None, end=None, slice_ticks=slice_ticks, budget_ticks=budget_ticks)
        start, end = budget['start'], budget['end']
        require(start >= last_capture and end == start + budget_ticks and end < 2**64-1, 'fixed budget')
        deadline = min(end, start + slice_ticks)
        previous = start
        completed = False
        saw_store = False
        for call in range(1, CALL_LIMIT + 1):
            begin = reader.take('call_begin', call=call, before=None, deadline=deadline)
            returned = reader.take('call_end', call=call, entered=None, after=None, status=0)
            entered, after = returned['entered'], returned['after']
            capture = reader.take('capture', call=call, captured=None, reason=None, rip=None, rax=nonce, witness=None)
            captured = capture['captured']
            require(previous <= begin['before'] <= entered < end and entered <= after <= captured <= end,
                    'late or nonmonotonic call/capture')
            require(capture['reason'] in (1, 52), 'unexpected/full VM-entry failure reason')
            require((capture['rip'], capture['witness']) in ((0x100, 0), (0x103, nonce)), 'false RIP/witness')
            require(not saw_store or (capture['rip'], capture['witness']) == (0x103, nonce), 'guest progress regressed')
            saw_store |= capture['witness'] == nonce
            calls += 1
            previous = captured
            if capture['reason'] == 52 and capture['witness'] == nonce:
                reader.take('witness', call=call, nonce=nonce, captured=captured)
                last_capture = captured
                max_calls = max(max_calls, call)
                completed = True
                break
            if capture['reason'] == 52:
                empty_slices += 1
                require(captured + slice_ticks < 2**64 - 1, 'renewal overflow')
                deadline = min(end, captured + slice_ticks)
            else:
                irqs += 1
        require(completed, 'no timer/store witness before call limit')
        reader.resource('cpu_destroy')
        reader.resource('unmap')
        if mode == 'vm':
            reader.resource('vm_destroy')
        reader.take('iteration_complete', nonce=nonce)
    if mode == 'vcpu':
        reader.resource('vm_destroy')
    reader.take('backing_released')
    reader.take('complete', iterations=iterations, live_resources=0)
    require(reader.index == len(reader.values), 'unexpected suffix')
    return {'kind': 'independent-real-mode-finite-audit', 'mode': mode, 'iterations': iterations,
            'owner': reader.owner, 'vm_generations': reader.vm, 'cpu_generations': reader.cpu,
            'calls': calls, 'max_calls_per_iteration': max_calls, 'empty_timer_slices': empty_slices,
            'irq_exits': irqs, 'complete_native_acceptance': False,
            'scope': 'event contract only; native exit and child retirement require separate verification',
            'output_sha256': hashlib.sha256(raw).hexdigest()}
