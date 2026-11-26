//! Client wire profiles (lyrebird): per-identity HTTP/2 handshake shapes.
//!
//! Wire data here is transcribed from the operator's 2026-11-22 tls.peet.ws
//! captures and pinned in lobsterbs/lyrebird `tools/capture/h2shapes.py`,
//! where each profile's akamai fingerprint string is md5-hash-gated:
//!
//! - Brave (Chromium 158, Win10):
//!   `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`
//!   (hash 52d84b11737d980aef856699f885ca86)
//! - Firefox 160:
//!   `1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s`
//!   (hash 6ea73faa8fc5aac76bded7bd238f6433)
//!
//! Both captures also set the PRIORITY flag on the first HEADERS frame:
//! Brave exclusive dep 0 weight 256, Firefox dep 0 weight 22 (wire stores
//! weight minus one).
//!
//! The default profile is stock h2 behavior. The Chromium profile preserves
//! the unconditional shape shipped 2026-11-23 (seed SETTINGS
//! ENABLE_PUSH/INITIAL_WINDOW_SIZE/MAX_FRAME_SIZE/MAX_CONCURRENT_STREAMS from
//! the builder, deferred connection window, stock pseudo order, no HEADERS
//! priority flag). Brave and Firefox are capture-pinned. The profile is
//! read at client handshake time, so a set applies to every connection
//! established afterwards; single-threaded wasm hosts set it once at
//! transport init.

use std::sync::atomic::{AtomicU8, Ordering};

/// The process-wide client wire profile. Read at client handshake time.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ClientWireProfile {
    /// Stock h2 behavior (upstream defaults).
    #[default]
    Default,
    /// The Chromium-compatible shape shipped 2026-11-23.
    Chromium,
    /// The pinned Brave (Chromium 158) capture.
    Brave,
    /// The pinned Firefox 160 capture.
    Firefox,
}

static CLIENT_WIRE_PROFILE: AtomicU8 = AtomicU8::new(0);

/// Set the process-wide client wire profile (Default = 0, Chromium = 1,
/// Brave = 2, Firefox = 3). Shorthand for `client::set_client_wire_profile`.
pub fn set_client_wire_profile(profile: ClientWireProfile) {
    CLIENT_WIRE_PROFILE.store(profile as u8, Ordering::Relaxed);
}

/// The current process-wide client wire profile.
pub fn client_wire_profile() -> ClientWireProfile {
    match CLIENT_WIRE_PROFILE.load(Ordering::Relaxed) {
        1 => ClientWireProfile::Chromium,
        2 => ClientWireProfile::Brave,
        3 => ClientWireProfile::Firefox,
        _ => ClientWireProfile::Default,
    }
}

/// The wire order of the request pseudo-headers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PseudoOrder {
    /// Stock h2: :method :scheme :authority :path (m,s,a,p).
    Msap,
    /// Chromium family: :method :authority :scheme :path (m,a,s,p).
    Masp,
    /// Firefox: :method :path :authority :scheme (m,p,a,s).
    Mpas,
}

/// The PRIORITY flag payload pinned for client HEADERS frames (applied to
/// every client HEADERS frame; weight is the wire value, weight minus one).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeadersPriority {
    pub exclusive: bool,
    pub dependency_id: u32,
    pub weight: u8,
}

/// The capture-pinned client handshake shape for a profile.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ClientHandshakeShape {
    /// Exact (setting id, value) pairs, in wire order.
    pub settings: &'static [(u16, u32)],
    /// The connection window target: the handshake emits a WINDOW_UPDATE of
    /// `target - DEFAULT_INITIAL_WINDOW_SIZE` right after the seed SETTINGS.
    pub connection_target: u32,
    /// INITIAL_WINDOW_SIZE local override (must match the wire).
    pub initial_window_size: u32,
    /// HEADER_TABLE_SIZE local override (matches the wire pair).
    pub header_table_size: u32,
    /// MAX_HEADER_LIST_SIZE local override (None keeps the builder value).
    pub max_header_list_size: Option<u32>,
    /// MAX_FRAME_SIZE local override (None keeps the builder value).
    pub max_frame_size: Option<u32>,
}

impl ClientWireProfile {
    /// The capture-pinned handshake shape (None for Default and Chromium,
    /// which keep the stock/builder-driven seed frames).
    pub(crate) fn handshake_shape(self) -> Option<ClientHandshakeShape> {
        match self {
            ClientWireProfile::Brave => Some(ClientHandshakeShape {
                settings: &[
                    (0x0001, 65_536),    // HEADER_TABLE_SIZE
                    (0x0002, 0),         // ENABLE_PUSH
                    (0x0004, 6_291_456), // INITIAL_WINDOW_SIZE (6 MiB)
                    (0x0006, 262_144),   // MAX_HEADER_LIST_SIZE
                ],
                // 65_535 + 15_663_105 = 15_728_640 (15 MiB connection window)
                connection_target: 15_728_640,
                initial_window_size: 6_291_456,
                header_table_size: 65_536,
                max_header_list_size: Some(262_144),
                max_frame_size: None,
            }),
            ClientWireProfile::Firefox => Some(ClientHandshakeShape {
                settings: &[
                    (0x0001, 65_536),  // HEADER_TABLE_SIZE
                    (0x0002, 0),       // ENABLE_PUSH
                    (0x0004, 131_072), // INITIAL_WINDOW_SIZE (128 KiB)
                    (0x0005, 16_384),  // MAX_FRAME_SIZE (Firefox sends no 6)
                ],
                // 65_535 + 12_517_377 = 12_582_912 (12 MiB connection window)
                connection_target: 12_582_912,
                initial_window_size: 131_072,
                header_table_size: 65_536,
                max_header_list_size: None,
                max_frame_size: Some(16_384),
            }),
            _ => None,
        }
    }

    /// The request pseudo-header wire order for this profile.
    pub fn pseudo_order(self) -> PseudoOrder {
        match self {
            ClientWireProfile::Brave => PseudoOrder::Masp,
            ClientWireProfile::Firefox => PseudoOrder::Mpas,
            // Chromium keeps the stock order it shipped with.
            ClientWireProfile::Chromium | ClientWireProfile::Default => PseudoOrder::Msap,
        }
    }

    /// The PRIORITY flag payload for client HEADERS frames, if the profile
    /// pins one (Chromium shipped without the flag; Default never sends it).
    pub fn headers_priority(self) -> Option<HeadersPriority> {
        match self {
            ClientWireProfile::Brave => Some(HeadersPriority {
                exclusive: true,
                dependency_id: 0,
                weight: 255, // weight 256, wire stores minus one
            }),
            ClientWireProfile::Firefox => Some(HeadersPriority {
                exclusive: false,
                dependency_id: 0,
                weight: 21, // weight 22, wire stores minus one
            }),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn akamai_fingerprint(profile: ClientWireProfile) -> String {
        let shape = profile.handshake_shape().expect("pinned shape");
        let settings = shape
            .settings
            .iter()
            .map(|(id, val)| format!("{id}:{val}"))
            .collect::<Vec<_>>()
            .join(";");
        let wu = shape.connection_target - crate::frame::DEFAULT_INITIAL_WINDOW_SIZE;
        let pseudo = match profile.pseudo_order() {
            PseudoOrder::Msap => "m,s,a,p",
            PseudoOrder::Masp => "m,a,s,p",
            PseudoOrder::Mpas => "m,p,a,s",
        };
        format!("{settings}|{wu}|0|{pseudo}")
    }

    #[test]
    fn brave_shape_matches_the_pinned_capture() {
        assert_eq!(
            akamai_fingerprint(ClientWireProfile::Brave),
            "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
        );
    }

    #[test]
    fn firefox_shape_matches_the_pinned_capture() {
        assert_eq!(
            akamai_fingerprint(ClientWireProfile::Firefox),
            "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s"
        );
    }

    #[test]
    fn default_and_chromium_have_no_pinned_shape() {
        assert!(ClientWireProfile::Default.handshake_shape().is_none());
        assert!(ClientWireProfile::Chromium.handshake_shape().is_none());
        assert_eq!(ClientWireProfile::Default.pseudo_order(), PseudoOrder::Msap);
        assert_eq!(
            ClientWireProfile::Chromium.pseudo_order(),
            PseudoOrder::Msap
        );
        assert!(ClientWireProfile::Default.headers_priority().is_none());
        assert!(ClientWireProfile::Chromium.headers_priority().is_none());
    }

    #[test]
    fn priorities_match_the_pinned_captures() {
        assert_eq!(
            ClientWireProfile::Brave.headers_priority(),
            Some(HeadersPriority {
                exclusive: true,
                dependency_id: 0,
                weight: 255
            })
        );
        assert_eq!(
            ClientWireProfile::Firefox.headers_priority(),
            Some(HeadersPriority {
                exclusive: false,
                dependency_id: 0,
                weight: 21
            })
        );
    }

    #[test]
    fn profile_round_trips_through_the_atomic() {
        set_client_wire_profile(ClientWireProfile::Default);
        assert_eq!(client_wire_profile(), ClientWireProfile::Default);
        set_client_wire_profile(ClientWireProfile::Brave);
        assert_eq!(client_wire_profile(), ClientWireProfile::Brave);
        set_client_wire_profile(ClientWireProfile::Firefox);
        assert_eq!(client_wire_profile(), ClientWireProfile::Firefox);
        set_client_wire_profile(ClientWireProfile::Chromium);
        assert_eq!(client_wire_profile(), ClientWireProfile::Chromium);
        set_client_wire_profile(ClientWireProfile::Default);
    }
}