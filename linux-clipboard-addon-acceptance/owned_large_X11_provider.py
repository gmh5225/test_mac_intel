"""Owned ICCCM INCR selection provider, restricted to generated Z fixtures.

Protocol: x.org ICCCM, INCR Properties. Each transfer is keyed by its requestor
window and property; a nonempty 32-bit INCR lower bound precedes data chunks.
"""
from pathlib import Path
import argparse
import ctypes as c
import hashlib
import json
import time


class SelectionRequest(c.Structure):
    _fields_ = [('type', c.c_int), ('serial', c.c_ulong), ('send_event', c.c_int), ('display', c.c_void_p),
        ('owner', c.c_ulong), ('requestor', c.c_ulong), ('selection', c.c_ulong), ('target', c.c_ulong),
        ('property', c.c_ulong), ('time', c.c_ulong)]


class Selection(c.Structure):
    _fields_ = [('type', c.c_int), ('serial', c.c_ulong), ('send_event', c.c_int), ('display', c.c_void_p),
        ('requestor', c.c_ulong), ('selection', c.c_ulong), ('target', c.c_ulong), ('property', c.c_ulong), ('time', c.c_ulong)]


class Property(c.Structure):
    _fields_ = [('type', c.c_int), ('serial', c.c_ulong), ('send_event', c.c_int), ('display', c.c_void_p),
        ('window', c.c_ulong), ('atom', c.c_ulong), ('time', c.c_ulong), ('state', c.c_int)]


class Event(c.Union):
    _fields_ = [('type', c.c_int), ('request', SelectionRequest), ('selection', Selection),
        ('property', Property), ('padding', c.c_long * 24)]


def main():
    parser = argparse.ArgumentParser()
    for name in ['input', 'ready', 'stop', 'report']:
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--display', choices=[':96', ':98'], required=True)
    parser.add_argument('--transport', choices=['incr', 'direct'], default='incr')
    args = parser.parse_args()
    data = args.input.read_bytes()
    assert 0 < len(data) <= 100000001 and data.count(90) == len(data)
    receipt = dict(status='started', bytes=len(data), sha256=hashlib.sha256(data).hexdigest(),
        generated_fill_byte=90, transport=args.transport, transfers=[], unknown_targets=[], host_display_used=False)
    x = c.CDLL('libX11.so.6')
    x.XOpenDisplay.argtypes = [c.c_char_p]; x.XOpenDisplay.restype = c.c_void_p
    x.XDefaultRootWindow.argtypes = [c.c_void_p]; x.XDefaultRootWindow.restype = c.c_ulong
    x.XCreateSimpleWindow.argtypes = [c.c_void_p, c.c_ulong, c.c_int, c.c_int, c.c_uint, c.c_uint, c.c_uint, c.c_ulong, c.c_ulong]; x.XCreateSimpleWindow.restype = c.c_ulong
    x.XInternAtom.argtypes = [c.c_void_p, c.c_char_p, c.c_int]; x.XInternAtom.restype = c.c_ulong
    x.XSetSelectionOwner.argtypes = [c.c_void_p, c.c_ulong, c.c_ulong, c.c_ulong]
    x.XGetSelectionOwner.argtypes = [c.c_void_p, c.c_ulong]; x.XGetSelectionOwner.restype = c.c_ulong
    x.XSelectInput.argtypes = [c.c_void_p, c.c_ulong, c.c_long]
    x.XChangeProperty.argtypes = [c.c_void_p, c.c_ulong, c.c_ulong, c.c_ulong, c.c_int, c.c_int, c.c_void_p, c.c_int]
    x.XSendEvent.argtypes = [c.c_void_p, c.c_ulong, c.c_int, c.c_long, c.POINTER(Event)]
    x.XPending.argtypes = [c.c_void_p]
    x.XNextEvent.argtypes = [c.c_void_p, c.POINTER(Event)]
    x.XSync.argtypes = [c.c_void_p, c.c_int]
    x.XFlush.argtypes = [c.c_void_p]
    x.XMaxRequestSize.argtypes = [c.c_void_p]; x.XMaxRequestSize.restype = c.c_long
    x.XExtendedMaxRequestSize.argtypes = [c.c_void_p]; x.XExtendedMaxRequestSize.restype = c.c_long
    x.XDestroyWindow.argtypes = [c.c_void_p, c.c_ulong]
    x.XCloseDisplay.argtypes = [c.c_void_p]
    display = x.XOpenDisplay(args.display.encode()); assert display
    window = x.XCreateSimpleWindow(display, x.XDefaultRootWindow(display), 0, 0, 1, 1, 0, 0, 0); assert window
    atoms = {name: x.XInternAtom(display, name.encode(), 0) for name in ['CLIPBOARD', 'TARGETS', 'UTF8_STRING', 'STRING', 'TEXT', 'INCR']}
    request_units = x.XExtendedMaxRequestSize(display) or x.XMaxRequestSize(display)
    chunk_size = min(8 * 1048576 if args.transport == 'direct' else 1048576, (request_units - 64) * 4)
    assert 65536 <= chunk_size <= 8 * 1048576
    receipt['chunk_size'] = chunk_size
    x.XSetSelectionOwner(display, atoms['CLIPBOARD'], window, 0); x.XSync(display, 0)
    assert x.XGetSelectionOwner(display, atoms['CLIPBOARD']) == window
    pending_ready = args.ready.with_name(args.ready.name + '.pending')
    pending_ready.write_text(json.dumps(dict(ready=True, owner=window, bytes=len(data), sha256=receipt['sha256'], atoms=atoms)) + '\n')
    pending_ready.replace(args.ready)
    active = {}
    started = time.monotonic()
    try:
        while True:
            if not x.XPending(display):
                if args.stop.exists():
                    break
                assert time.monotonic() - started < 90
                time.sleep(.001); continue
            event = Event(); x.XNextEvent(display, c.byref(event))
            if event.type == 30:
                request = event.request
                assert request.owner == window and request.selection == atoms['CLIPBOARD']
                prop = request.property or request.target
                accepted = prop
                if request.target == atoms['TARGETS']:
                    targets = (c.c_ulong * 4)(atoms['TARGETS'], atoms['UTF8_STRING'], atoms['STRING'], atoms['TEXT'])
                    x.XChangeProperty(display, request.requestor, prop, 4, 32, 0, targets, len(targets))
                elif request.target in [atoms['UTF8_STRING'], atoms['STRING'], atoms['TEXT']]:
                    key = (request.requestor, prop); assert key not in active
                    if args.transport == 'incr':
                        x.XSelectInput(display, request.requestor, 1 << 22)
                        lower_bound = c.c_ulong(len(data))
                        x.XChangeProperty(display, request.requestor, prop, atoms['INCR'], 32, 0, c.byref(lower_bound), 1)
                        row = dict(window=request.requestor, property=prop, target=request.target, lower_bound=len(data),
                            marker_elements=1, data_bytes=0, chunks=0, terminal_sent=False, terminal_delete_received=False)
                        receipt['transfers'].append(row)
                        active[key] = row
                    else:
                        chunks = 0
                        for offset in range(0, len(data), chunk_size):
                            block = data[offset:offset + chunk_size]; buffer = c.create_string_buffer(block)
                            x.XChangeProperty(display, request.requestor, prop, request.target, 8, 0 if offset == 0 else 2, buffer, len(block))
                            chunks += 1
                        receipt['transfers'].append(dict(window=request.requestor, property=prop, target=request.target,
                            direct_property=True, data_bytes=len(data), chunks=chunks))
                else:
                    receipt['unknown_targets'].append(request.target); accepted = 0
                x.XSync(display, 0)
                reply = Event(); reply.selection = Selection(type=31, display=display, requestor=request.requestor,
                    selection=request.selection, target=request.target, property=accepted, time=request.time)
                assert x.XSendEvent(display, request.requestor, 0, 0, c.byref(reply)) == 1
                x.XFlush(display)
            elif event.type == 28 and event.property.state == 1:
                key = (event.property.window, event.property.atom)
                if key not in active:
                    continue
                row = active[key]
                if row['terminal_sent']:
                    row['terminal_delete_received'] = True; del active[key]; continue
                offset = row['data_bytes']; block = data[offset:offset + chunk_size]
                buffer = c.create_string_buffer(block) if block else None
                # Append after each acknowledged deletion, as required by ICCCM.
                x.XChangeProperty(display, key[0], key[1], row['target'], 8, 2, buffer, len(block))
                x.XFlush(display)
                if block:
                    row['data_bytes'] += len(block); row['chunks'] += 1
                else:
                    assert offset == len(data); row['terminal_sent'] = True
        receipt['status'] = 'owned_X11_provider_stopped'
    finally:
        x.XDestroyWindow(display, window); x.XCloseDisplay(display)
        args.report.write_text(json.dumps(receipt, indent=2) + '\n')


if __name__ == '__main__':
    main()
