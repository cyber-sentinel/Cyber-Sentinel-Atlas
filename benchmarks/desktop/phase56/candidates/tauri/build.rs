use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

const ICON_WIDTH: u32 = 32;
const ICON_HEIGHT: u32 = 32;

fn is_git_sha(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn resolve_build_source_sha() -> String {
    println!("cargo:rerun-if-env-changed=ATLAS_SOURCE_SHA");
    println!("cargo:rerun-if-env-changed=GITHUB_SHA");

    for name in ["ATLAS_SOURCE_SHA", "GITHUB_SHA"] {
        if let Ok(value) = env::var(name) {
            let normalized = value.trim().to_ascii_lowercase();
            assert!(
                is_git_sha(&normalized),
                "{name} must be an exact 40-character hexadecimal Git SHA"
            );
            return normalized;
        }
    }

    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is required"));
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(&manifest_dir)
        .output()
        .expect("ATLAS_SOURCE_SHA/GITHUB_SHA unset and git rev-parse could not run");
    assert!(
        output.status.success(),
        "ATLAS_SOURCE_SHA/GITHUB_SHA unset and Git source identity is unavailable"
    );
    let value = String::from_utf8(output.stdout)
        .expect("git rev-parse returned non-UTF-8 output")
        .trim()
        .to_ascii_lowercase();
    assert!(
        is_git_sha(&value),
        "git rev-parse did not return an exact 40-character hexadecimal Git SHA"
    );
    value
}

fn push_u16_le(buffer: &mut Vec<u8>, value: u16) {
    buffer.extend_from_slice(&value.to_le_bytes());
}

fn push_u32_le(buffer: &mut Vec<u8>, value: u32) {
    buffer.extend_from_slice(&value.to_le_bytes());
}

fn push_i32_le(buffer: &mut Vec<u8>, value: i32) {
    buffer.extend_from_slice(&value.to_le_bytes());
}

fn set_pixel(pixels: &mut [[u8; 4]], x: i32, y: i32, color: [u8; 4]) {
    if x < 0 || y < 0 || x >= ICON_WIDTH as i32 || y >= ICON_HEIGHT as i32 {
        return;
    }
    pixels[(y as u32 * ICON_WIDTH + x as u32) as usize] = color;
}

fn draw_line(pixels: &mut [[u8; 4]], mut x0: i32, mut y0: i32, x1: i32, y1: i32, color: [u8; 4]) {
    let dx = (x1 - x0).abs();
    let sx = if x0 < x1 { 1 } else { -1 };
    let dy = -(y1 - y0).abs();
    let sy = if y0 < y1 { 1 } else { -1 };
    let mut error = dx + dy;
    loop {
        set_pixel(pixels, x0, y0, color);
        set_pixel(pixels, x0 + 1, y0, color);
        set_pixel(pixels, x0, y0 + 1, color);
        if x0 == x1 && y0 == y1 {
            break;
        }
        let doubled = 2 * error;
        if doubled >= dy {
            error += dy;
            x0 += sx;
        }
        if doubled <= dx {
            error += dx;
            y0 += sy;
        }
    }
}

fn write_deterministic_windows_icon() -> PathBuf {
    const PIXEL_BYTES: u32 = ICON_WIDTH * ICON_HEIGHT * 4;
    const MASK_ROW_BYTES: u32 = ICON_WIDTH.div_ceil(32) * 4;
    const MASK_BYTES: u32 = MASK_ROW_BYTES * ICON_HEIGHT;
    const DIB_BYTES: u32 = 40 + PIXEL_BYTES + MASK_BYTES;
    const IMAGE_OFFSET: u32 = 6 + 16;

    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is required"));
    let icon_dir = manifest_dir.join("icons");
    fs::create_dir_all(&icon_dir).expect("failed to create deterministic Tauri icon directory");
    let icon_path = icon_dir.join("icon.ico");

    // Deterministic ATLAS mark: dark field, cyan hex shell and a high-contrast A glyph.
    // The icon is generated during build so no binary asset is added to source control.
    let background = [0x1d, 0x13, 0x07, 0xff];
    let cyan = [0xff, 0xd2, 0x55, 0xff];
    let white = [0xff, 0xfd, 0xec, 0xff];
    let mut pixels = vec![background; (ICON_WIDTH * ICON_HEIGHT) as usize];

    let hex = [
        (16, 2),
        (28, 9),
        (28, 23),
        (16, 30),
        (4, 23),
        (4, 9),
        (16, 2),
    ];
    for pair in hex.windows(2) {
        draw_line(
            &mut pixels,
            pair[0].0,
            pair[0].1,
            pair[1].0,
            pair[1].1,
            cyan,
        );
    }
    draw_line(&mut pixels, 10, 24, 16, 8, white);
    draw_line(&mut pixels, 16, 8, 22, 24, white);
    draw_line(&mut pixels, 12, 19, 20, 19, cyan);

    let mut icon = Vec::with_capacity((IMAGE_OFFSET + DIB_BYTES) as usize);
    push_u16_le(&mut icon, 0);
    push_u16_le(&mut icon, 1);
    push_u16_le(&mut icon, 1);
    icon.push(ICON_WIDTH as u8);
    icon.push(ICON_HEIGHT as u8);
    icon.push(0);
    icon.push(0);
    push_u16_le(&mut icon, 1);
    push_u16_le(&mut icon, 32);
    push_u32_le(&mut icon, DIB_BYTES);
    push_u32_le(&mut icon, IMAGE_OFFSET);

    push_u32_le(&mut icon, 40);
    push_i32_le(&mut icon, ICON_WIDTH as i32);
    push_i32_le(&mut icon, (ICON_HEIGHT * 2) as i32);
    push_u16_le(&mut icon, 1);
    push_u16_le(&mut icon, 32);
    push_u32_le(&mut icon, 0);
    push_u32_le(&mut icon, PIXEL_BYTES);
    push_i32_le(&mut icon, 0);
    push_i32_le(&mut icon, 0);
    push_u32_le(&mut icon, 0);
    push_u32_le(&mut icon, 0);

    // ICO DIB pixel rows are stored bottom-up in BGRA order.
    for y in (0..ICON_HEIGHT).rev() {
        for x in 0..ICON_WIDTH {
            icon.extend_from_slice(&pixels[(y * ICON_WIDTH + x) as usize]);
        }
    }
    icon.resize((IMAGE_OFFSET + DIB_BYTES) as usize, 0);
    fs::write(&icon_path, &icon).expect("failed to write deterministic Tauri Windows icon");
    icon_path
}

fn configure_windows_gui_subsystem() {
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
        && env::var("PROFILE").as_deref() == Ok("release")
    {
        // Match rustc's Windows GUI-subsystem behavior: keep Rust's generated
        // `main` entrypoint while preventing the packaged GUI host from
        // allocating a companion console. atlas-core separately uses
        // CREATE_NO_WINDOW when spawned by the host.
        println!("cargo:rustc-link-arg=/SUBSYSTEM:WINDOWS");
        println!("cargo:rustc-link-arg=/ENTRY:mainCRTStartup");
    }
}

fn main() {
    let source_sha = resolve_build_source_sha();
    println!("cargo:rustc-env=ATLAS_BUILD_SOURCE_SHA={source_sha}");
    configure_windows_gui_subsystem();
    let icon_path = write_deterministic_windows_icon();
    let windows = tauri_build::WindowsAttributes::new().window_icon_path(icon_path);
    let app_manifest = tauri_build::AppManifest::new().commands(&[
        "core_status",
        "search_records",
        "list_entities",
        "get_record",
        "expand_graph",
        "pack_status",
        "pack_update",
        "pack_rollback",
    ]);
    let attributes = tauri_build::Attributes::new()
        .windows_attributes(windows)
        .app_manifest(app_manifest);
    tauri_build::try_build(attributes).expect("failed to run Tauri build script");
}
