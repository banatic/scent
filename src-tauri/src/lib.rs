mod deep;
mod emit;
mod etw;
mod exporter;
mod ipc;
mod launcher;
mod modmap;
mod model;
mod store;
mod tracker;

#[cfg(test)]
mod capture_smoke;

use ipc::AppState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState::new())
        .setup(|app| {
            // Native Mica backdrop so the Liquid Glass chrome sits on a real OS
            // material rather than a faked gradient. Windows 11 only.
            #[cfg(target_os = "windows")]
            {
                use tauri::Manager;
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window_vibrancy::apply_mica(&window, None);
                }
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            // Stop the ETW session when the window closes so a real-time trace
            // isn't left running after the app exits.
            if matches!(event, tauri::WindowEvent::Destroyed) {
                use tauri::Manager;
                ipc::stop_capture_inner(window.app_handle().state::<AppState>().inner());
            }
        })
        .invoke_handler(tauri::generate_handler![
            ipc::start_capture,
            ipc::stop_capture,
            ipc::get_status,
            ipc::get_process_tree,
            ipc::query_events,
            ipc::get_event_detail,
            ipc::get_deep_findings,
            ipc::export_report
        ])
        .run(tauri::generate_context!())
        .expect("error while running scent");
}
