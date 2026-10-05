import copy
import json
import unittest
from intel_api_contract import audit, CONTROLS, STATE_FIELDS, SLICE_NS, BUDGET_NS, CALL_LIMIT


def fixture(mode='vcpu', iterations=2, retries=()):
    events=[]; vm=cpu=iteration=thread_ns=0
    def event(kind, **kw):
        events.append(dict(event=kind, seq=len(events)+1, iteration=iteration, owner=57,
                           vm_generation=vm, cpu_generation=cpu, **kw))
    def resource(operation):
        nonlocal vm,cpu
        event('resource',operation=operation,phase='begin')
        vm+=operation=='vm_create'; cpu+=operation=='cpu_create'
        event('resource',operation=operation,phase='end',status=0)
    event('program',version=3,mode=mode,iterations=iterations,memory_bytes=65536,
          guest_hex='a30002ebfe',timebase_numer=1,timebase_denom=1,
          slice_ns=SLICE_NS,budget_ns=BUDGET_NS,call_limit=CALL_LIMIT,event_limit=65536)
    if mode=='vcpu': resource('vm_create')
    for iteration in range(1,iterations+1):
        event('iteration_begin',nonce=iteration)
        if mode=='vm': resource('vm_create')
        resource('map'); resource('cpu_create'); event('reset',value=0)
        for field,required,forbidden in CONTROLS:
            event('control',field=field,required=required,forbidden=forbidden,must=0,may=0xffffffff,
                  effective=required,observed=required)
        for field,requested,forbidden in [(0x6800,0x20,0x80000001),(0x6804,0x2000,0x20)]:
            event('control_register',field=field,requested=requested,forbidden=forbidden,
                  must=0,may=0xffffffff,fixed=0,allowed=0xffffffff,effective=requested,observed=requested)
        event('state',nonce=iteration,cr0=0x20,cr4=0x2000,zero_other_gprs=True,fields=copy.deepcopy(STATE_FIELDS))
        start=iteration*10*BUDGET_NS; end=start+BUDGET_NS; deadline=start+SLICE_NS; now=start
        event('budget',start=start,end=end,slice_ticks=SLICE_NS,budget_ticks=BUDGET_NS)
        exec_ns=13
        for call,reason in enumerate([*retries,52],1):
            progress=call==len(retries)+1
            event('call_begin',call=call,before=now,deadline=deadline)
            pre_started,pre_finished=now+1,now+2
            entered=now+3; now+=50
            event('call_end',call=call,entered=entered,after=now,status=0)
            now+=5
            event('capture',call=call,captured=now,reason=reason,rip=0x103 if progress else 0x100,
                  rax=iteration,witness=iteration if progress else 0)
            if reason==52 and not progress: deadline=now+SLICE_NS
            event('accounting',call=call,pre_started=pre_started,pre_finished=pre_finished,
                  exec_before_ns=exec_ns,thread_before_ns=thread_ns,
                  post_started=now+1,post_finished=now+3,
                  exec_after_ns=exec_ns+17,thread_after_ns=thread_ns+42)
            captured=now; now+=5; exec_ns+=17; thread_ns+=42
        event('witness',call=call,nonce=iteration,captured=captured)
        resource('cpu_destroy'); resource('unmap')
        if mode=='vm': resource('vm_destroy')
        event('iteration_complete',nonce=iteration)
    if mode=='vcpu': resource('vm_destroy')
    event('backing_released'); event('complete',iterations=iterations,live_resources=0)
    return events


def raw(events): return ('\n'.join(json.dumps(e) for e in events)+'\n').encode()


class Contract(unittest.TestCase):
    def test_accounting_reset_is_per_vcpu_and_thread_is_continuous(self):
        result=audit(raw(fixture(retries=[1,52,1])),'vcpu',2)
        self.assertEqual(result['cpu_generations'],2)
        for key,iteration,call in [('exec_before_ns',1,2),('thread_before_ns',2,1)]:
            events=fixture(retries=[1])
            item=next(e for e in events if e['event']=='accounting' and e['iteration']==iteration and e['call']==call)
            item[key]=0
            with self.assertRaises(ValueError):audit(raw(events),'vcpu',2)
    def test_accounting_fields_types_and_brackets(self):
        mutations=[('exec_after_ns',0),('thread_after_ns',-1),('exec_before_ns',True),
                   ('thread_before_ns',1.0),('post_finished',2**64),('pre_started',0),
                   ('pre_finished',22_000_000_000),('post_started',0),('post_finished',0),('call',2)]
        for key,value in mutations:
            with self.subTest(key=key,value=value):
                events=fixture(); next(e for e in events if e['event']=='accounting')[key]=value
                with self.assertRaises(ValueError):audit(raw(events),'vcpu',2)
        for change in ('missing','extra','failure'):
            events=fixture(); index=next(i for i,e in enumerate(events) if e['event']=='accounting')
            if change=='missing':events.pop(index)
            elif change=='extra':events[index]['status']=0
            else:events[index]['event']='error'
            with self.assertRaises(ValueError):audit(raw(events),'vcpu',2)
    def test_post_sampling_does_not_relax_capture_or_allow_time_reversal(self):
        events=fixture(retries=[1]); measured=next(e for e in events if e['event']=='accounting')
        measured['post_finished']=20_000_000_061
        with self.assertRaises(ValueError):audit(raw(events),'vcpu',2)
        events=fixture(); capture=next(e for e in events if e['event']=='capture')
        capture['captured']=22_000_000_001
        measured=next(e for e in events if e['event']=='accounting')
        measured.update(post_started=22_000_000_002,post_finished=22_000_000_003)
        with self.assertRaisesRegex(ValueError,'late or nonmonotonic'):audit(raw(events),'vcpu',2)
    def test_lf_framing_preserves_json_whitespace_but_rejects_blank_records(self):
        data=raw(fixture())
        for ending in (b'\n',b'\r\n',b'\r\r\n'):
            self.assertEqual(audit(data.replace(b'\n',ending),'vcpu',2)['iterations'],2)
        for value in (data.replace(b'\n',b'\n\n',1),data.replace(b'\n',b'\r\n\r\n',1)):
            with self.assertRaises(ValueError):audit(value,'vcpu',2)
    def test_entry_time_excludes_logging_and_requires_remaining_budget(self):
        for entered in (19_999_999_999,22_000_000_000,22_000_000_001):
            events=fixture();next(e for e in events if e['event']=='call_end')['entered']=entered
            with self.assertRaises(ValueError):audit(raw(events),'vcpu',2)
        events=fixture();returned=next(e for e in events if e['event']=='call_end')
        returned['entered']=returned['after']+1
        with self.assertRaises(ValueError):audit(raw(events),'vcpu',2)
    def test_rejected_entry_or_api_failure_cannot_supply_a_capture(self):
        for kind in ('entry_rejected','error'):
            events=fixture();index=next(i for i,e in enumerate(events) if e['event']=='call_end')
            events[index]['event']=kind
            with self.assertRaises(ValueError):audit(raw(events),'vcpu',2)
    def test_complete_both_lifetimes(self):
        for mode in ['vcpu','vm']:
            result=audit(raw(fixture(mode,1000)),mode)
            self.assertEqual(result['iterations'],1000)
            self.assertEqual(result['cpu_generations'],1000)
            self.assertEqual(result['vm_generations'],1000 if mode=='vm' else 1)
            self.assertFalse(result['complete_native_acceptance'])
    def test_irq_and_empty_timer_retries(self):
        result=audit(raw(fixture(retries=[1,52,1])),'vcpu',2)
        self.assertEqual((result['empty_timer_slices'],result['irq_exits']),(2,4))
    def test_missing_reordered_duplicate_events(self):
        for change in ['drop','duplicate','reorder']:
            events=fixture()
            if change=='drop': events.pop(7)
            elif change=='duplicate': events.insert(7,copy.deepcopy(events[7]))
            else: events[7],events[8]=events[8],events[7]
            with self.assertRaises(ValueError): audit(raw(events),'vcpu',2)
    def test_each_critical_observation(self):
        mutations=[('capture','witness',0),('capture','rip',0x100),('capture','rax',999),
            ('capture','reason',52|(1<<31)),('capture','captured',2**63),('capture','call',2),
            ('call_end','status',1),('call_end','after',2**63),('call_begin','deadline',1),
            ('budget','end',2**63),('budget','slice_ticks',1),('reset','value',1),
            ('control','observed',0),('control','must',2**63),('control_register','effective',1),
            ('state','cr0',0x21),('state','zero_other_gprs',1),('iteration_complete','nonce',0),
            ('complete','live_resources',1),('program','timebase_numer',0),('program','guest_hex','90')]
        for kind,key,value in mutations:
            with self.subTest(kind=kind,key=key):
                events=fixture(); next(e for e in events if e['event']==kind)[key]=value
                with self.assertRaises(ValueError): audit(raw(events),'vcpu',2)
    def test_boolean_cannot_replace_state_integer(self):
        events=fixture();next(e for e in events if e['event']=='state')['fields'][1][1]=False
        with self.assertRaises(ValueError): audit(raw(events),'vcpu',2)
    def test_irq_cannot_renew_slice(self):
        events=fixture(retries=[1]);calls=[e for e in events if e['event']=='call_begin']
        calls[1]['deadline']+=55
        with self.assertRaises(ValueError): audit(raw(events),'vcpu',2)
    def test_empty_timer_must_renew_full_slice(self):
        events=fixture(retries=[52]);calls=[e for e in events if e['event']=='call_begin']
        calls[1]['deadline']-=1
        with self.assertRaises(ValueError): audit(raw(events),'vcpu',2)
    def test_no_cleanup_or_extra_tail(self):
        data=fixture()
        for value in [data[:-1],data[:-2],data+[data[-1]]]:
            with self.assertRaises(ValueError): audit(raw(value),'vcpu',2)
    def test_wrong_owner_and_generations(self):
        for key,value in [('owner',58),('vm_generation',2),('cpu_generation',2),('iteration',2)]:
            events=fixture();next(e for e in events if e['event']=='capture')[key]=value
            with self.assertRaises(ValueError): audit(raw(events),'vcpu',2)
    def test_incomplete_and_duplicate_json(self):
        data=raw(fixture())
        for value in [data[:-1],data+b'{',data.replace(b'"seq": 1,',b'"seq": 1,"seq": 1,',1),
                      data.replace(b'"seq": 1,',b'"seq": 1.0,',1)]:
            with self.assertRaises(ValueError): audit(value,'vcpu',2)
    def test_stale_nonce_in_later_iteration(self):
        events=fixture();capture=next(e for e in events if e['event']=='capture' and e['iteration']==2)
        capture['witness']=1
        with self.assertRaises(ValueError): audit(raw(events),'vcpu',2)
    def test_budget_remains_fixed_after_retry(self):
        events=fixture(retries=[52]);capture=[e for e in events if e['event']=='capture'][1]
        capture['captured']=22_000_000_001
        with self.assertRaises(ValueError): audit(raw(events),'vcpu',2)
    def test_progress_through_irqs_is_monotonic(self):
        events=fixture(retries=[1,1])
        for e in events:
            if e['event']=='capture': e['rip'],e['witness']=0x103,e['iteration']
        self.assertEqual(audit(raw(events),'vcpu',2)['irq_exits'],4)
        captures=[e for e in events if e['event']=='capture']
        captures[1]['rip'],captures[1]['witness']=0x100,0
        with self.assertRaises(ValueError): audit(raw(events),'vcpu',2)

if __name__=='__main__': unittest.main()
