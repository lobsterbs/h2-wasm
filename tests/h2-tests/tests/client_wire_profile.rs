//! Per-identity client wire profile integration tests (lyrebird).
//!
//! Each pinned profile is proven on the wire with a loose mock: the exact
//! seed SETTINGS bytes (proving wire order, not just values), the connection
//! WINDOW_UPDATE sent at the handshake, the SETTINGS ACK, and the PRIORITY
//! flag on the first request HEADERS frame. The capture truth lives in
//! lobsterbs/lyrebird `tools/capture/h2shapes.py` (2026-11-22 tls.peet.ws
//! captures):
//!
//! - Brave:   `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`
//! - Firefox: `1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s`
//!
//! Default must keep stock h2 behavior and Chromium must keep the shape the
//! engine shipped with (the 2026-11-23 Chromium SETTINGS seed, no handshake
//! WINDOW_UPDATE, no HEADERS priority flag).
//!
//! The raw byte reads happen before the first codec stream poll so the
//! Handle's frame parser cannot consume the frames first.

use h2_support::prelude::*;

use std::sync::MutexGuard;

static PROFILE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Hold the profile for the duration of one test; serialize the tests on a
/// static lock (the profile is process-global) and restore Default on drop.
struct ProfileGuard(MutexGuard<'static, ()>);

impl ProfileGuard {
    fn new(profile: h2::client::ClientWireProfile) -> Self {
        let guard = PROFILE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        h2::client::set_client_wire_profile(profile);
        ProfileGuard(guard)
    }
}

impl Drop for ProfileGuard {
    fn drop(&mut self) {
        h2::client::set_client_wire_profile(h2::client::ClientWireProfile::Default);
    }
}

async fn drive_request(io: mock::Mock) {
    let h2 = async move {
        let (mut client, h2) = client::handshake(io).await.unwrap();
        tokio::spawn(async move {
            let request = Request::builder()
                .uri("https://http2.akamai.com/")
                .body(())
                .unwrap();
            let _res = client
                .send_request(request, true)
                .unwrap()
                .0
                .await
                .expect("request");
        });
        h2.await.expect("h2");
    };
    h2.await;
}

/// Read `buf.len()` raw bytes straight off the pipe (before any frame parse).
async fn read_raw(srv: &mut mock::Handle, buf: &mut [u8]) {
    tokio_io::AsyncReadExt::read_exact(srv, buf)
        .await
        .expect("raw read");
}

/// One raw frame: 9-byte head + `len` payload bytes, returned as a Vec.
async fn read_raw_frame(srv: &mut mock::Handle) -> Vec<u8> {
    let mut head = [0u8; 9];
    read_raw(srv, &mut head).await;
    let len = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
    let mut frame = head.to_vec();
    frame.resize(9 + len, 0);
    read_raw(srv, &mut frame[9..]).await;
    frame
}

#[tokio::test]
async fn brave_client_sends_the_pinned_handshake() {
    h2_support::trace_init!();
    let _g = ProfileGuard::new(h2::client::ClientWireProfile::Brave);

    let (io, mut srv) = mock::new();

    let srv = async move {
        // Send the server settings first so the client can ACK them as
        // soon as its connection is polled.
        srv.send_frame(frames::settings()).await;
        srv.read_preface().await.unwrap();

        // The pinned Brave seed SETTINGS, byte-exact (wire order proven):
        // 1:65536, 2:0, 4:6291456, 6:262144.
        let seed = read_raw_frame(&mut srv).await;
        assert_eq!(
            seed,
            [
                0, 0, 24, 4, 0, 0, 0, 0, 0, // SETTINGS, len 24, no flags
                0, 1, 0x00, 0x01, 0x00, 0x00, // HEADER_TABLE_SIZE 65536
                0, 2, 0x00, 0x00, 0x00, 0x00, // ENABLE_PUSH 0
                0, 4, 0x00, 0x60, 0x00, 0x00, // INITIAL_WINDOW_SIZE 6291456
                0, 6, 0x00, 0x04, 0x00, 0x00, // MAX_HEADER_LIST_SIZE 262144
            ]
        );

        // The connection WINDOW_UPDATE at the handshake: 15,663,105
        // (wire bytes 00 ef 00 01). A spurious second update (double
        // accounting) would surface as a different next frame.
        let wu = read_raw_frame(&mut srv).await;
        assert_eq!(wu, [0, 0, 4, 8, 0, 0, 0, 0, 0, 0x00, 0xef, 0x00, 0x01]);

        srv.recv_frame(frames::settings_ack()).await;
        // The request HEADERS carry the pinned priority payload:
        // exclusive dep 0 weight 256 (wire 0xff), END_STREAM set.
        srv.recv_frame(
            frames::headers(1)
                .request("GET", "https://http2.akamai.com/")
                .eos()
                .priority(true, 0, 255),
        )
        .await;
        srv.send_frame(frames::headers(1).response(200).eos()).await;
    };

    join(srv, drive_request(io)).await;
}

#[tokio::test]
async fn firefox_client_sends_the_pinned_handshake() {
    h2_support::trace_init!();
    let _g = ProfileGuard::new(h2::client::ClientWireProfile::Firefox);

    let (io, mut srv) = mock::new();

    let srv = async move {
        srv.send_frame(frames::settings()).await;
        srv.read_preface().await.unwrap();

        // The pinned Firefox seed SETTINGS, byte-exact:
        // 1:65536, 2:0, 4:131072, 5:16384.
        let seed = read_raw_frame(&mut srv).await;
        assert_eq!(
            seed,
            [
                0, 0, 24, 4, 0, 0, 0, 0, 0, // SETTINGS, len 24, no flags
                0, 1, 0x00, 0x01, 0x00, 0x00, // HEADER_TABLE_SIZE 65536
                0, 2, 0x00, 0x00, 0x00, 0x00, // ENABLE_PUSH 0
                0, 4, 0x00, 0x02, 0x00, 0x00, // INITIAL_WINDOW_SIZE 131072
                0, 5, 0x00, 0x00, 0x40, 0x00, // MAX_FRAME_SIZE 16384
            ]
        );

        // The connection WINDOW_UPDATE at the handshake: 12,517,377
        // (wire bytes 00 bf 00 01).
        let wu = read_raw_frame(&mut srv).await;
        assert_eq!(wu, [0, 0, 4, 8, 0, 0, 0, 0, 0, 0x00, 0xbf, 0x00, 0x01]);

        srv.recv_frame(frames::settings_ack()).await;
        // The request HEADERS carry the pinned priority payload:
        // dep 0 weight 22 (wire 0x15), not exclusive.
        srv.recv_frame(
            frames::headers(1)
                .request("GET", "https://http2.akamai.com/")
                .eos()
                .priority(false, 0, 21),
        )
        .await;
        srv.send_frame(frames::headers(1).response(200).eos()).await;
    };

    join(srv, drive_request(io)).await;
}

#[tokio::test]
async fn default_client_is_stock_h2() {
    h2_support::trace_init!();
    let _g = ProfileGuard::new(h2::client::ClientWireProfile::Default);

    let (io, mut srv) = mock::new();

    let srv = async move {
        let settings = srv.assert_client_handshake().await;
        assert_default_settings!(settings);
        // No handshake WINDOW_UPDATE, no priority flag: the request
        // HEADERS frame comes right after the ACK with stock flags.
        srv.recv_frame(
            frames::headers(1)
                .request("GET", "https://http2.akamai.com/")
                .eos(),
        )
        .await;
        srv.send_frame(frames::headers(1).response(200).eos()).await;
    };

    join(srv, drive_request(io)).await;
}

#[tokio::test]
async fn chromium_client_keeps_the_shipped_seed_shape() {
    h2_support::trace_init!();
    let _g = ProfileGuard::new(h2::client::ClientWireProfile::Chromium);

    let (io, mut srv) = mock::new();

    let srv = async move {
        srv.send_frame(frames::settings()).await;
        srv.read_preface().await.unwrap();

        // The Chromium seed shipped 2026-11-23, byte-exact:
        // 2:0, 4:65535, 5:16384, 3:1024.
        let seed = read_raw_frame(&mut srv).await;
        assert_eq!(
            seed,
            [
                0, 0, 24, 4, 0, 0, 0, 0, 0, // SETTINGS, len 24, no flags
                0, 2, 0x00, 0x00, 0x00, 0x00, // ENABLE_PUSH 0
                0, 4, 0x00, 0x00, 0xff, 0xff, // INITIAL_WINDOW_SIZE 65535
                0, 5, 0x00, 0x00, 0x40, 0x00, // MAX_FRAME_SIZE 16384
                0, 3, 0x00, 0x00, 0x04, 0x00, // MAX_CONCURRENT_STREAMS 1024
            ]
        );

        // No handshake WINDOW_UPDATE (the target is deferred).
        srv.recv_frame(frames::settings_ack()).await;
        // No priority flag on the request HEADERS.
        srv.recv_frame(
            frames::headers(1)
                .request("GET", "https://http2.akamai.com/")
                .eos(),
        )
        .await;
        srv.send_frame(frames::headers(1).response(200).eos()).await;
    };

    join(srv, drive_request(io)).await;
}