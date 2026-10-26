use gpui_kit::{AssetSource, SharedString};
use std::borrow::Cow;

#[derive(rust_embed::RustEmbed)]
#[folder = "assets/flags/"]
struct Flags;

pub struct Assets;

impl AssetSource for Assets {
  fn load(&self, path: &str) -> anyhow::Result<Option<Cow<'static, [u8]>>> {
    if let Some(name) = path.strip_prefix("flags/") {
      return Ok(Flags::get(name).map(|file| file.data));
    }
    gpui_kit::assets::Assets.load(path)
  }

  fn list(&self, path: &str) -> anyhow::Result<Vec<SharedString>> {
    if path.starts_with("flags/") {
      return Ok(
        Flags::iter()
          .map(|name| format!("flags/{name}").into())
          .collect(),
      );
    }
    gpui_kit::assets::Assets.list(path)
  }
}

pub fn flag(code: &str) -> Option<String> {
  if code.len() != 2 || !code.bytes().all(|b| b.is_ascii_alphabetic()) {
    return None;
  }
  let name = format!("{}.svg", code.to_ascii_lowercase());
  Flags::get(&name).map(|_| format!("flags/{name}"))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn flags_are_embedded_and_invalid_codes_have_a_fallback() {
    for code in ["FR", "CH", "NL", "DE", "US", "JP"] {
      let path = flag(code).unwrap();
      let asset = Assets.load(&path).unwrap().unwrap();
      assert!(std::str::from_utf8(&asset).unwrap().contains("<svg"));
    }
    assert!(flag("../fr").is_none());
    assert!(flag("ZZ").is_none());
  }
}
