use std::collections::{HashMap, HashSet};
use log::{trace};
use skim::{ItemPreview, SkimItemSender, PreviewContext, Skim, SkimItem, SkimItemReceiver};
use skim::prelude::*;

use crate::gpg::{get_enabled_keygrip, SshKeyInfo, mark_gpg_key_as_ssh_key, unmark_gpg_key_as_ssh_key, gpg_keys};

struct MyItem {
    ssh_key_info: SshKeyInfo,
}

impl SkimItem for MyItem {
    fn text(&self) -> Cow<str> {
        Cow::Borrowed(&self.ssh_key_info.main_name)
    }

    fn preview(&self, _context: PreviewContext) -> ItemPreview {
        let cert_key_id = self.ssh_key_info.main_key_id.as_str();
        let auth_keygrip = self.ssh_key_info.auth_keygrip.as_str();
        ItemPreview::Text(format!(
            "Key ID (Cert): {cert_key_id}\n\
            Keygrip (Auth): {auth_keygrip}"
        ))
    }
}

struct MySelector {
    toggl_keygrip: HashSet<String>,
}

impl Selector for MySelector {
    fn should_select(&self, _index: usize, item: &dyn SkimItem) -> bool {
        self.toggl_keygrip.contains(item.text().as_str())
    }
}

pub(crate) fn fzf_set(ssh_keys_info: Vec<SshKeyInfo>) {
    let keygrip = get_enabled_keygrip();

    let (tx_item, rx_item): (SkimItemSender, SkimItemReceiver) = unbounded();

    let selected = HashSet::from_iter(
        ssh_keys_info.iter().filter(
            |ssh_key_info| {
                tx_item.send(Arc::new(MyItem {
                    ssh_key_info: (*ssh_key_info).clone(),
                })).unwrap();
                keygrip.contains(ssh_key_info.auth_keygrip.as_str())
            }
        ).map(|ssh_keys_info| ssh_keys_info.main_name.clone())
    );

    drop(tx_item); // so that skim could know when to stop waiting for more items.

    let my_selector = Rc::new(MySelector {
        toggl_keygrip: selected,
    });


    let mut options = SkimOptionsBuilder::default()
        .height(Some("50%"))
        .multi(true)
        .preview(Some("")) // preview should be specified to enable preview window
        .no_clear_start(true)
        .multi(true)
        .build()
        .unwrap();

    options.selector = Some(my_selector);

    let selected_items = Skim::run_with(&options, Some(rx_item)).map(
        |out| {
            if out.is_abort {
                trace!("Fuzzer was aborted");
                None
            } else {
                Some(out.selected_items)
            }
        }).unwrap_or(None);

    if let Some(selected_items) = selected_items {
        let lookup: HashMap<String, &SshKeyInfo> = HashMap::from_iter(
            ssh_keys_info.iter().map(|info| {
                (info.main_name.clone(), info)
            }
        ));

        let mut keygrip_selected = HashSet::new();
        let mut missing_keygrip = Vec::new();
        
        for selected_item in selected_items {
            let item= lookup.get(&selected_item.text().to_string()).unwrap();
            trace!("Select item: `{:?}`", item);
            if ! keygrip.contains(&item.auth_keygrip) { missing_keygrip.push(item.auth_keygrip.as_str()) }
            keygrip_selected.insert(item.auth_keygrip.clone());
        }
        mark_gpg_key_as_ssh_key(&missing_keygrip);
        
        let remove_keygrip = Vec::from_iter(&keygrip - &keygrip_selected);
        unmark_gpg_key_as_ssh_key(&remove_keygrip);
    }
}


pub(crate) fn fzf_copy_id() -> Vec<String> {
    let gpg_keys = gpg_keys(None);
    let enabled_keygrip = get_enabled_keygrip();

    let (tx_item, rx_item): (SkimItemSender, SkimItemReceiver) = unbounded();

    let mut key_info_by_name: HashMap<String, SshKeyInfo> = HashMap::new();
    // let mut key_info_by_keygrip = HashMap::new();
    for info in gpg_keys {
        key_info_by_name.insert(info.main_name.clone(), info.clone());
        // key_info_by_keygrip.insert(info.keygrip, &info);

        if enabled_keygrip.contains(&info.auth_keygrip) {
            tx_item.send(Arc::new(MyItem {
                ssh_key_info: info.clone(),
            })).unwrap();
        }
    }

    let options = SkimOptionsBuilder::default()
        .height(Some("50%"))
        .multi(true)
        .preview(Some("")) // preview should be specified to enable preview window
        .no_clear_start(true)
        .multi(true)
        .build()
        .unwrap();

    let selected_items = Skim::run_with(&options, Some(rx_item)).map(
        |out| {
            if out.is_abort {
                trace!("Fuzzer was aborted");
                Vec::new()
            } else {
                out.selected_items
            }
        }).unwrap_or(Vec::new());

    selected_items.iter().filter_map(|item| {
        key_info_by_name.get(
            item.text().to_string().as_str()
        ).map(|info| (*info).clone().main_key_id.to_string())
    }).collect()
}
