use std::env;
use std::fs;
use std::path::PathBuf;

fn push_u16_le(buffer: &mut Vec<u8>, value: u16) {
    buffer.extend_from_slice(&value.to_le_bytes());
}

fn push_u32_le(buffer: &mut Vec<u8>, value: u32) {
    buffer.extend_from_slice(&value.to_le_bytes());
}

fn push_i32_le(buffer: &mut Vec<u8>, value: i32) {
    buffer.extend_from_slice(&value.to_le_bytes());
}

fn write_deterministic_windows_icon() -> PathBuf {
    const WIDTH: u32 = 16;
    const HEIGHT: u32 = 16;
    const PIXEL_BYTES: u32 = WIDTH * HEIGHT * 4;
    const MASK_ROW_BYTES: u32 = WIDTH.div_ceil(32) * 4;
    const MASK_BYTES: u32 = MASK_ROW_BYTES * HEIGHT;
    const DIB_BYTES: u32 = 40 + PIXEL_BYTES + MASK_BYTES;
    const IMAGE_OFFSET: u32 = 6 + 16;

    let manifest_dir = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is required"),
    );
    let icon_dir = manifest_dir.join("icons");
    fs::create_dir_all(&icon_dir).expect("failed to create deterministic Tauri icon directory");
    let icon_path = icon_dir.join("icon.ico");

    let mut icon = Vec::with_capacity((IMAGE_OFFSET + DIB_BYTES) as usize);

    // ICONDIR
    push_u16_le(&mut icon, 0); // reserved
    push_u16_le(&mut icon, 1); // image type: icon
    push_u16_le(&mut icon, 1); // image count

    // ICONDIRENTRY
    icon.push(WIDTH as u8);
    icon.push(HEIGHT as u8);
    icon.push(0); // palette size: no palette
    icon.push(0); // reserved
    push_u16_le(&mut icon, 1); // planes
    push_u16_le(&mut icon, 32); // bits per pixel
    push_u32_le(&mut icon, DIB_BYTES);
    push_u32_le(&mut icon, IMAGE_OFFSET);

    // BITMAPINFOHEADER. ICO stores XOR and AND masks vertically, so the
    // encoded DIB height is twice the visible height.
    push_u32_le(&mut icon, 40);
    push_i32_le(&mut icon, WIDTH as i32);
    push_i32_le(&mut icon, (HEIGHT * 2) as i32);
    push_u16_le(&mut icon, 1);
    push_u16_le(&mut icon, 32);
    push_u32_le(&mut icon, 0); // BI_RGB
    push_u32_le(&mut icon, PIXEL_BYTES);
    push_i32_le(&mut icon, 0);
    push_i32_le(&mut icon, 0);
    push_u32_le(&mut icon, 0);
    push_u32_le(&mut icon, 0);

    // Deterministic opaque dark-blue BGRA pixels. This is a build-only
    // placeholder, not a product branding asset.
    for _ in 0..(WIDTH * HEIGHT) {
        icon.extend_from_slice(&[0x20, 0x12, 0x0b, 0xff]);
    }

    // Fully opaque AND mask, DWORD-aligned per ICO/BMP row.
    icon.resize((IMAGE_OFFSET + DIB_BYTES) as usize, 0);

    fs::write(&icon_path, &icon).expect("failed to write deterministic Tauri Windows icon");
    icon_path
}

fn main() {
    let icon_path = write_deterministic_windows_icon();
    let windows = tauri_build::WindowsAttributes::new().window_icon_path(icon_path);
    let app_manifest = tauri_build::AppManifest::new().commands(&["core_status"]);
    let attributes = tauri_build::Attributes::new()
        .windows_attributes(windows)
        .app_manifest(app_manifest);
    tauri_build::try_build(attributes).expect("failed to run Tauri build script");
}
