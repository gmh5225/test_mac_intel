from pathlib import Path
import ctypes as C,hashlib,json,math,os,random,sys,time
work,input_name,path_name,bits,name,order=sys.argv[1:]
w=Path(work);bits=int(bits);libs={}
class Span(C.Structure):_fields_=[('offset',C.c_size_t),('size',C.c_size_t),('ip',C.c_uint64)]
class Result(C.Structure):_fields_=[(k,C.c_uint64) for k in ('instructions','rejected','boundaries','values')]
source=Path(input_name).read_bytes();data=(C.c_uint8*len(source)).from_buffer_copy(source)
spans=[Span(*map(int,line.split())) for line in Path(path_name).read_text().splitlines()]
assert all(f.size and f.offset+f.size<=len(source) for f in spans);arr=(Span*len(spans))(*spans)
addresses={}
for key in order.split(','):
    api=C.CDLL(str(w/(key+'.dylib')),mode=os.RTLD_LOCAL|os.RTLD_NOW)
    api.bench_create.argtypes=[C.c_uint,C.c_uint];api.bench_create.restype=C.c_void_p
    api.bench_close.argtypes=[C.c_void_p];api.bench_close.restype=None
    api.bench_run.argtypes=[C.c_void_p,C.POINTER(C.c_uint8),C.POINTER(Span),C.c_size_t,C.c_uint,C.POINTER(Result)];api.bench_run.restype=None
    api.bench_text_address.argtypes=[];api.bench_text_address.restype=C.c_void_p
    addresses[key]=[api.bench_text_address(),C.cast(api.bench_run,C.c_void_p).value];libs[key]=api
libs['base'].bench_qos()
assert addresses['base']!=addresses['candidate'] and addresses['duplicate']!=addresses['candidate']
report={}
for mode in (0,1,2):
    states={k:api.bench_create(bits,mode)for k,api in libs.items()}
    def take(k,reps):
        r=Result();cpu=time.process_time_ns();wall=time.perf_counter_ns()
        libs[k].bench_run(states[k],data,arr,len(spans),reps,C.byref(r))
        ticks=[time.process_time_ns()-cpu,time.perf_counter_ns()-wall]
        return ticks,[r.instructions,r.rejected,r.boundaries,r.values]
    reps=max(1,math.ceil(55e6/take('base',1)[0][0]))
    want=take('base',reps)[1];assert want[0]>0 and all(take(k,reps)[1]==want for k in libs)
    rng=random.Random(f'{name}/{mode}/macos-native-dso');keys=sorted(libs);cycles=[]
    for _ in range(17):
        rng.shuffle(keys);times={k:[] for k in keys}
        for k in keys+keys[::-1]:
            row,v=take(k,reps);assert v==want;times[k].append(row)
        cycles.append({k:[sum(a[i] for a in v)for i in (0,1)]for k,v in times.items()})
    report[mode]=dict(repeats=reps,values=want,cycles=cycles)
    for k,api in libs.items():api.bench_close(states[k])
print(json.dumps(dict(name=name,bits=bits,order=order,addresses=addresses,report=report)))
