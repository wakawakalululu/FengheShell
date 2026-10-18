use slint::Image;

/// Colours derived from a wallpaper, pushed into the Theme global so panels,
/// accent and backgrounds harmonise with the image.
#[derive(Clone, Copy, Debug)]
pub struct Palette {
    /// Wallpaper is dark overall → use the dark base palette.
    pub is_dark: bool,
    /// Vivid accent colour sharing the wallpaper's dominant hue.
    pub accent: (u8, u8, u8),
    /// Average colour, used to subtly tint panel/background surfaces.
    pub tint: (u8, u8, u8),
}

pub struct Wallpaper {
    pub image: Image,
    pub palette: Palette,
}
