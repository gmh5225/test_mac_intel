//! Private test compositor, using the attributed wl-clipboard-rs test state.
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use wayland_server::{Display, ListeningSocket};
use wayland_protocols_wlr::data_control::v1::server::zwlr_data_control_manager_v1::ZwlrDataControlManagerV1;

#[macro_export]
macro_rules! server_ignore_global_impl {
    ($handler:ty => [$($iface:ty),*]) => { $(
        impl wayland_server::GlobalDispatch<$iface, ()> for $handler {
            fn bind(_: &mut Self, _: &wayland_server::DisplayHandle, _: &wayland_server::Client,
                    id: wayland_server::New<$iface>, _: &(), data: &mut wayland_server::DataInit<'_, Self>) {
                data.init(id, ());
            }
        }
    )* };
}

pub struct TestServer<S: 'static> { pub display: Display<S> }
#[path = "../state.rs"]
mod state;
use state::{OfferInfo, SeatInfo, State};

struct ClientState;
impl wayland_backend::server::ClientData for ClientState {}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert_eq!(args.len(), 5);
    let mode = &args[1];
    let ready = Path::new(&args[2]);
    let stop = Path::new(&args[3]);
    let report = Path::new(&args[4]);
    let mut server = TestServer { display: Display::<State>::new().unwrap() };
    let socket = ListeningSocket::bind_auto("clipboard-owned", 0..100).unwrap();
    let socket_name = socket.socket_name().unwrap().to_str().unwrap();
    let offer = |text: &str| Some(OfferInfo::Buffered {
        data: vec![("text/plain;charset=utf-8".into(), text.as_bytes().to_vec())],
    });
    let mut state = State {
        seats: HashMap::from([("seat0".into(), SeatInfo {
            offer: if mode == "empty" { None } else { offer("owned clipboard fixture\n") },
            primary_offer: if mode == "empty" { None } else { offer("自有 primary 🧪\n") },
        })]),
        ..Default::default()
    };
    state.create_seats(&server);
    server.display.handle().create_global::<State, ZwlrDataControlManagerV1, ()>(if mode == "v1" { 1 } else { 2 }, ());
    std::fs::write(ready, format!("{{\"ready\":true,\"socket\":\"{socket_name}\",\"version\":{}}}\n", if mode == "v1" {1} else {2})).unwrap();
    let mut connections = 0usize;
    while !stop.exists() {
        while let Some(stream) = socket.accept().unwrap() {
            server.display.handle().insert_client(stream, Arc::new(ClientState)).unwrap();
            connections += 1;
        }
        server.display.dispatch_clients(&mut state).unwrap();
        server.display.flush_clients().unwrap();
        std::thread::sleep(Duration::from_millis(1));
    }
    std::fs::write(report, format!("{{\"connections\":{connections},\"source_objects\":{},\"seats\":{},\"stopped\":true}}\n", state.sources.len(), state.seats.len())).unwrap();
}
