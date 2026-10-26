use gpui_kit::{size, App, Asset, AssetSource, DevicePixels, ImageCacheError, ImageSource, RenderImage, SharedString, SvgSize};
use std::{borrow::Cow, future::Future, sync::Arc};

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

pub fn flag_image(path: String) -> ImageSource {
  ImageSource::from(move |window: &mut gpui_kit::Window, cx: &mut App| {
    let scale = window.scale_factor();
    let source = (path.clone(), (16. * scale).ceil() as i32, (12. * scale).ceil() as i32);
    window.use_asset::<FlagImage>(&source, cx)
  })
}

struct FlagImage;

impl Asset for FlagImage {
  type Source = (String, i32, i32);
  type Output = Result<Arc<RenderImage>, ImageCacheError>;

  fn load((path, width, height): Self::Source, cx: &mut App) -> impl Future<Output = Self::Output> + Send + 'static {
    let renderer = cx.svg_renderer();
    async move {
      render_flag(&renderer, &path, width, height)
    }
  }
}

fn render_flag(renderer: &gpui_kit::SvgRenderer, path: &str, width: i32, height: i32) -> Result<Arc<RenderImage>, ImageCacheError> {
  let bytes = Assets.load(path)
    .and_then(|asset| asset.ok_or_else(|| anyhow::anyhow!("Missing flag: {path}")))
    .map_err(|error| ImageCacheError::Other(Arc::new(error)))?;
  let svg = renderer.parse_svg(&bytes)?;
  // GPUI's default image loader rasterizes the full SVG viewBox, regardless of layout size.
  renderer.render_parsed(&svg, SvgSize::Size(size(DevicePixels(width), DevicePixels(height)))).map_err(Into::into)
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

  #[test]
  fn flags_rasterize_at_display_resolution_including_hidpi() {
    let renderer = gpui_kit::SvgRenderer::new(Arc::new(Assets));
    for name in Flags::iter().filter(|name| name.ends_with(".svg")) {
      for (width, height) in [(16, 12), (24, 18), (32, 24)] {
        let image = render_flag(&renderer, &format!("flags/{name}"), width, height).unwrap();
        assert_eq!(image.size(0), size(DevicePixels(width), DevicePixels(height)), "{name}");
      }
    }
  }
}
