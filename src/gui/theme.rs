use gpui_kit::{rgb, Hsla};
use gpui_omarchy::Theme;
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Deserialize)]
pub struct Palette {
  background: String,
  surface: String,
  foreground: String,
  accent: String,
  border: String,
  error: String,
}

fn color(value: &str) -> Option<Hsla> {
  let value = value.strip_prefix('#')?;
  if value.len() != 6 {
    return None;
  }
  u32::from_str_radix(value, 16)
    .ok()
    .map(|value| rgb(value).into())
}

pub fn path() -> Option<PathBuf> {
  crate::core::config::AppConfig::config_dir()
    .ok()
    .map(|dir| dir.join("theme.json"))
}

pub fn monarch() -> Theme {
  let mut theme = Theme::tokyo_night();
  theme.name = "Monarch".into();
  theme.accent = rgb(0xbb9af7).into();
  theme.selection = rgb(0x302448).into();
  theme.border = rgb(0x393f5c).into();
  theme.secondary = rgb(0x8992b8).into();
  theme.font = theme.mono_font.clone();
  theme
}

pub fn parse(contents: &[u8]) -> Option<Theme> {
  let palette: Palette = serde_json::from_slice(contents).ok()?;
  let mut theme = monarch();
  theme.background = color(&palette.background)?;
  theme.surface = color(&palette.surface)?;
  theme.foreground = color(&palette.foreground)?;
  theme.accent = color(&palette.accent)?;
  theme.border = color(&palette.border)?;
  theme.danger = color(&palette.error)?;
  theme.bright = theme.foreground;
  theme.secondary = theme.foreground;
  theme.inset = theme.background;
  theme.selection = theme.surface;
  theme.on_accent = theme.background;
  if theme.background.l > 0.5 {
    theme.appearance = gpui_kit::base::ThemeAppearance::Light;
    theme.success = rgb(0x426626).into();
    theme.warning = rgb(0x855b00).into();
  }
  Some(theme)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn rejects_partial_or_invalid_palettes() {
    assert!(parse(br##"{"background":"#ffffff"}"##).is_none());
    assert!(color("#gg0011").is_none());
    assert!(color("fff").is_none());
  }

  #[test]
  fn light_palette_sets_readable_status_colors() {
    let theme = parse(br##"{"background":"#ffffff","surface":"#eeeeee","foreground":"#222222","accent":"#7722aa","border":"#aaaaaa","error":"#aa0000"}"##).unwrap();
    assert_eq!(theme.appearance, gpui_kit::base::ThemeAppearance::Light);
    assert!(theme.success.l < 0.5);
  }
}
