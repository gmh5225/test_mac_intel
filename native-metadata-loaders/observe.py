"""Observe named exports and calendar output in the host's native Windows process."""
import ctypes
from ctypes import wintypes
import hashlib
import json
from pathlib import Path
import struct

root=Path(__file__).resolve().parent
spec=json.loads((root/"providers.json").read_text())
kernel=ctypes.WinDLL("kernel32",use_last_error=True)
kernel.GetCurrentProcess.restype=wintypes.HANDLE
kernel.IsWow64Process2.argtypes=[wintypes.HANDLE,ctypes.POINTER(wintypes.USHORT),ctypes.POINTER(wintypes.USHORT)]
process,native=wintypes.USHORT(),wintypes.USHORT()
assert kernel.IsWow64Process2(kernel.GetCurrentProcess(),ctypes.byref(process),ctypes.byref(native))
assert process.value==0 and native.value==0xAA64
kernel.GetModuleFileNameW.argtypes=[wintypes.HMODULE,wintypes.LPWSTR,wintypes.DWORD]
kernel.GetModuleFileNameW.restype=wintypes.DWORD
modules={}
for item in spec["providers"].values():
    module=item["module"]
    if module not in modules:
        try:
            dll=ctypes.WinDLL(module)
            name=ctypes.create_unicode_buffer(32768)
            assert 0 < kernel.GetModuleFileNameW(dll._handle,name,len(name)) < len(name)
            file=Path(name.value);data=file.read_bytes()
            machine=struct.unpack_from("<H",data,struct.unpack_from("<I",data,0x3c)[0]+4)[0]
            modules[module]={"path":str(file),"sha256":hashlib.sha256(data).hexdigest(),"machine":machine,"names":{}}
        except OSError as e:
            modules[module]={"error":str(e),"names":{}}
    rec=modules[module]
    symbols=sorted(item["exports"]|item["targets"]["arm64"]["additional_exports"])
    if "error" not in rec:
        dll=ctypes.WinDLL(module)
        rec["names"].update({s:bool(getattr(dll,s,None)) for s in symbols})

class CalendarDate(ctypes.Structure):
    _fields_=[(v,ctypes.c_uint32) for v in ("CalId","Era","Year","Month","Day","DayOfWeek","Hour","Minute","Second","Tick")]

cal=kernel.GetCalendarSupportedDateRange
cal.argtypes=[ctypes.c_uint32,ctypes.POINTER(CalendarDate),ctypes.POINTER(CalendarDate)]
cal.restype=ctypes.c_int
assert ctypes.sizeof(CalendarDate)==40
returns=[]
for identifier in (1,3,0):
    lo,hi=CalendarDate(),CalendarDate()
    result=cal(identifier,ctypes.byref(lo),ctypes.byref(hi))
    returns.append(dict(calendar=identifier,result=result,low=bytes(lo).hex(),high=bytes(hi).hex()))
report=dict(process=process.value,native=native.value,modules=modules,expected=returns)
Path("native-metadata.json").write_text(json.dumps(report,indent=2)+"\n")
assert not any("error" in m for m in modules.values()),modules
assert sum(len(m["names"]) for m in modules.values())==77 and all(x for m in modules.values() for x in m["names"].values())
assert returns[0]["result"] and returns[0]["low"]!=returns[0]["high"] and not returns[-1]["result"],returns
