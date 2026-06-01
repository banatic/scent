//! Sigma field adapter: the *only* bridge between scent's internal `Event` model
//! and the Sigma rule engine.
//!
//! `sigma_view` maps one captured event to a Sigma `logsource.category` plus the
//! standard Sigma field names that category's rules match on (Sysmon-style:
//! `Image`, `CommandLine`, `TargetObject`, `TargetFilename`, …). `Parent*` fields
//! are resolved through the process tree (`node_id -> parent_node_id`).
//!
//! `provided_fields` is the authoritative set of fields this adapter can ever
//! emit per category. The rule loader uses it to skip rules that reference a
//! field scent can't supply, and the curation script (`scripts/curate_sigma.py`)
//! hard-codes the same lists — **keep them in sync.**

use std::collections::BTreeMap;

use crate::model::{basename, Event, EventKind, FileOp, NetDir, ProcessNode, RegOp};
use crate::store::Capture;

/// Sigma `logsource.category` values scent can produce telemetry for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SigmaCategory {
    ProcessCreation,
    RegistrySet,
    RegistryEvent,
    DnsQuery,
    NetworkConnection,
    FileEvent,
    FileAccess,
    ImageLoad,
}

impl SigmaCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            SigmaCategory::ProcessCreation => "process_creation",
            SigmaCategory::RegistrySet => "registry_set",
            SigmaCategory::RegistryEvent => "registry_event",
            SigmaCategory::DnsQuery => "dns_query",
            SigmaCategory::NetworkConnection => "network_connection",
            SigmaCategory::FileEvent => "file_event",
            SigmaCategory::FileAccess => "file_access",
            SigmaCategory::ImageLoad => "image_load",
        }
    }

    /// Parse a rule's `logsource.category` string into a category scent supports.
    pub fn from_str(s: &str) -> Option<SigmaCategory> {
        Some(match s {
            "process_creation" => SigmaCategory::ProcessCreation,
            "registry_set" => SigmaCategory::RegistrySet,
            "registry_event" | "registry_add" | "registry_delete" => SigmaCategory::RegistryEvent,
            "dns_query" | "dns" => SigmaCategory::DnsQuery,
            "network_connection" => SigmaCategory::NetworkConnection,
            "file_event" => SigmaCategory::FileEvent,
            "file_access" => SigmaCategory::FileAccess,
            "image_load" => SigmaCategory::ImageLoad,
            _ => return None,
        })
    }

    /// Fields this adapter can emit for the category. Authoritative for rule
    /// loadability; mirrored by `scripts/curate_sigma.py`.
    pub fn provided_fields(self) -> &'static [&'static str] {
        match self {
            SigmaCategory::ProcessCreation => &[
                "Image",
                "OriginalFileName",
                "CommandLine",
                "ParentImage",
                "ParentCommandLine",
            ],
            SigmaCategory::RegistrySet => &["TargetObject", "EventType", "Image"],
            SigmaCategory::RegistryEvent => &["TargetObject", "EventType", "Image"],
            SigmaCategory::DnsQuery => &["QueryName", "QueryResults", "Image"],
            SigmaCategory::NetworkConnection => {
                &["DestinationIp", "DestinationPort", "Initiated", "Protocol", "Image"]
            }
            SigmaCategory::FileEvent => &["TargetFilename", "Image"],
            SigmaCategory::FileAccess => &["TargetFilename", "Image"],
            SigmaCategory::ImageLoad => &["ImageLoaded", "Image"],
        }
    }
}

/// The process whose action this event represents (the actor node's image).
fn actor_image<'a>(ev: &Event, cap: &'a Capture) -> Option<&'a ProcessNode> {
    ev.node_id.and_then(|id| cap.node(id))
}

/// Map a captured event to its Sigma category and standard field map, or `None`
/// for events with no Sigma logsource (e.g. process exit).
pub fn sigma_view(ev: &Event, cap: &Capture) -> Option<(SigmaCategory, BTreeMap<String, String>)> {
    let mut f: BTreeMap<String, String> = BTreeMap::new();
    let cat = match &ev.kind {
        EventKind::ProcCreate {
            image, cmdline, ..
        } => {
            // The ProcCreate event is attributed to the PARENT node, so the actor
            // node is the parent; Image/CommandLine come from the child payload.
            f.insert("Image".into(), image.clone());
            f.insert("OriginalFileName".into(), basename(image));
            if let Some(cl) = cmdline {
                f.insert("CommandLine".into(), cl.clone());
            }
            if let Some(parent) = actor_image(ev, cap) {
                f.insert("ParentImage".into(), parent.image.clone());
                if let Some(pcl) = &parent.cmdline {
                    f.insert("ParentCommandLine".into(), pcl.clone());
                }
            }
            SigmaCategory::ProcessCreation
        }
        EventKind::RegOp { op, path, value } => {
            // TargetObject follows the Sysmon convention: key path, value name
            // appended for value operations.
            let target = match value {
                Some(v) if !v.is_empty() => format!("{path}\\{v}"),
                _ => path.clone(),
            };
            f.insert("TargetObject".into(), target);
            f.insert("EventType".into(), reg_event_type(*op).into());
            if let Some(n) = actor_image(ev, cap) {
                f.insert("Image".into(), n.image.clone());
            }
            match op {
                RegOp::SetValue | RegOp::DeleteValue => SigmaCategory::RegistrySet,
                RegOp::CreateKey | RegOp::DeleteKey => SigmaCategory::RegistryEvent,
            }
        }
        EventKind::Dns { query, results, .. } => {
            f.insert("QueryName".into(), query.clone());
            if let Some(r) = results {
                f.insert("QueryResults".into(), r.clone());
            }
            if let Some(n) = actor_image(ev, cap) {
                f.insert("Image".into(), n.image.clone());
            }
            SigmaCategory::DnsQuery
        }
        EventKind::NetConn {
            proto,
            direction,
            remote,
            remote_port,
            ..
        } => {
            f.insert("DestinationIp".into(), remote.clone());
            f.insert("DestinationPort".into(), remote_port.to_string());
            f.insert(
                "Initiated".into(),
                matches!(direction, NetDir::Outbound).to_string(),
            );
            f.insert("Protocol".into(), format!("{proto:?}").to_lowercase());
            if let Some(n) = actor_image(ev, cap) {
                f.insert("Image".into(), n.image.clone());
            }
            SigmaCategory::NetworkConnection
        }
        EventKind::FileOp { op, path } => {
            f.insert("TargetFilename".into(), path.clone());
            if let Some(n) = actor_image(ev, cap) {
                f.insert("Image".into(), n.image.clone());
            }
            // Reads/opens are accesses; create/write/delete/rename are file events.
            match op {
                FileOp::Read | FileOp::Open => SigmaCategory::FileAccess,
                _ => SigmaCategory::FileEvent,
            }
        }
        EventKind::ImageLoad { image, .. } => {
            f.insert("ImageLoaded".into(), image.clone());
            if let Some(n) = actor_image(ev, cap) {
                f.insert("Image".into(), n.image.clone());
            }
            SigmaCategory::ImageLoad
        }
        EventKind::ProcExit { .. } => return None,
    };
    Some((cat, f))
}

fn reg_event_type(op: RegOp) -> &'static str {
    match op {
        RegOp::CreateKey => "CreateKey",
        RegOp::SetValue => "SetValue",
        RegOp::DeleteKey => "DeleteKey",
        RegOp::DeleteValue => "DeleteValue",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Category, FileOp, Proto, RegOp};
    use crate::store::Captured;

    /// Build a capture with a cmd root that spawned notepad, plus a few events.
    fn fixture() -> Capture {
        let mut cap = Capture::new(999);
        cap.seed_root(
            100,
            999,
            0,
            "C:\\Windows\\System32\\cmd.exe".into(),
            Some("\"cmd.exe\" /c stuff".into()),
        );
        cap.ingest(Captured::ProcCreate {
            pid: 200,
            ppid: 100,
            start_key: 1,
            image: "C:\\Windows\\System32\\notepad.exe".into(),
            cmdline: Some("notepad.exe secret.txt".into()),
        });
        cap
    }

    fn last_of(cap: &Capture, c: Category) -> Event {
        cap.events()
            .iter()
            .rev()
            .find(|e| e.category == c)
            .cloned()
            .expect("event present")
    }

    #[test]
    fn process_creation_fields() {
        let cap = fixture();
        let ev = last_of(&cap, Category::Process);
        let (cat, f) = sigma_view(&ev, &cap).unwrap();
        assert_eq!(cat, SigmaCategory::ProcessCreation);
        assert_eq!(f["Image"], "C:\\Windows\\System32\\notepad.exe");
        assert_eq!(f["OriginalFileName"], "notepad.exe");
        assert_eq!(f["CommandLine"], "notepad.exe secret.txt");
        assert_eq!(f["ParentImage"], "C:\\Windows\\System32\\cmd.exe");
        assert_eq!(f["ParentCommandLine"], "\"cmd.exe\" /c stuff");
    }

    #[test]
    fn registry_set_fields() {
        let mut cap = fixture();
        cap.ingest(Captured::Reg {
            pid: 100,
            op: RegOp::SetValue,
            path: "\\REGISTRY\\MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run".into(),
            value: Some("Evil".into()),
        });
        let ev = last_of(&cap, Category::Registry);
        let (cat, f) = sigma_view(&ev, &cap).unwrap();
        assert_eq!(cat, SigmaCategory::RegistrySet);
        assert_eq!(
            f["TargetObject"],
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Evil"
        );
        assert_eq!(f["EventType"], "SetValue");
        assert_eq!(f["Image"], "C:\\Windows\\System32\\cmd.exe");
    }

    #[test]
    fn registry_createkey_is_registry_event() {
        let mut cap = fixture();
        cap.ingest(Captured::Reg {
            pid: 100,
            op: RegOp::CreateKey,
            path: "\\REGISTRY\\MACHINE\\Software\\Foo".into(),
            value: None,
        });
        let ev = last_of(&cap, Category::Registry);
        let (cat, f) = sigma_view(&ev, &cap).unwrap();
        assert_eq!(cat, SigmaCategory::RegistryEvent);
        assert_eq!(f["TargetObject"], "HKLM\\Software\\Foo");
        assert_eq!(f["EventType"], "CreateKey");
    }

    #[test]
    fn network_connection_fields() {
        let mut cap = fixture();
        cap.ingest(Captured::Net {
            pid: 200,
            proto: Proto::Tcp,
            direction: NetDir::Outbound,
            local: "10.0.0.5:51000".into(),
            remote: "93.184.216.34".into(),
            remote_port: 443,
        });
        let ev = last_of(&cap, Category::Network);
        let (cat, f) = sigma_view(&ev, &cap).unwrap();
        assert_eq!(cat, SigmaCategory::NetworkConnection);
        assert_eq!(f["DestinationIp"], "93.184.216.34");
        assert_eq!(f["DestinationPort"], "443");
        assert_eq!(f["Initiated"], "true");
        assert_eq!(f["Protocol"], "tcp");
        assert_eq!(f["Image"], "C:\\Windows\\System32\\notepad.exe");
    }

    #[test]
    fn dns_query_fields() {
        let mut cap = fixture();
        cap.ingest(Captured::Dns {
            pid: 100,
            query: "evil.example.com".into(),
            qtype: 1,
            results: Some("93.184.216.34".into()),
        });
        let ev = last_of(&cap, Category::Dns);
        let (cat, f) = sigma_view(&ev, &cap).unwrap();
        assert_eq!(cat, SigmaCategory::DnsQuery);
        assert_eq!(f["QueryName"], "evil.example.com");
        assert_eq!(f["QueryResults"], "93.184.216.34");
    }

    #[test]
    fn file_event_vs_access() {
        let mut cap = fixture();
        cap.ingest(Captured::File {
            pid: 200,
            op: FileOp::Create,
            path: "C:\\Users\\v\\AppData\\Local\\Temp\\dropper.exe".into(),
        });
        let ev = last_of(&cap, Category::File);
        let (cat, f) = sigma_view(&ev, &cap).unwrap();
        assert_eq!(cat, SigmaCategory::FileEvent);
        assert_eq!(f["TargetFilename"], "C:\\Users\\v\\AppData\\Local\\Temp\\dropper.exe");

        cap.ingest(Captured::File {
            pid: 200,
            op: FileOp::Read,
            path: "C:\\Users\\v\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data"
                .into(),
        });
        let ev = last_of(&cap, Category::File);
        let (cat, _f) = sigma_view(&ev, &cap).unwrap();
        assert_eq!(cat, SigmaCategory::FileAccess);
    }

    #[test]
    fn image_load_fields() {
        let mut cap = fixture();
        cap.ingest(Captured::Image {
            pid: 200,
            image: "C:\\Windows\\System32\\amsi.dll".into(),
            base: 0x7fff_0000_0000,
        });
        let ev = last_of(&cap, Category::Module);
        let (cat, f) = sigma_view(&ev, &cap).unwrap();
        assert_eq!(cat, SigmaCategory::ImageLoad);
        assert_eq!(f["ImageLoaded"], "C:\\Windows\\System32\\amsi.dll");
    }

    #[test]
    fn proc_exit_has_no_sigma_view() {
        let mut cap = fixture();
        cap.ingest(Captured::ProcExit {
            pid: 200,
            exit_code: Some(0),
        });
        let ev = last_of(&cap, Category::Process);
        // The most recent process event is the exit.
        assert!(matches!(ev.kind, EventKind::ProcExit { .. }));
        assert!(sigma_view(&ev, &cap).is_none());
    }
}
