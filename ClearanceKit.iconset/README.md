# ClearanceKit — macOS App Icon

Direction: **Soft shield silhouette** — lowercase ck monogram with the k's terminal extended into a check stroke, sitting on a low-contrast classic shield form.

## Files

- `ClearanceKit.svg` — vector source (1024×1024)
- `icon_*.png` — rasters at every macOS .icns size

## Building the .icns

The `@` character cannot be used in this filesystem, so `@2x` files ship as `_2x`. Rename and build:

```bash
# 1. Rename folder if needed
# (already named ClearanceKit.iconset)

# 2. Restore @ in @2x filenames
cd ClearanceKit.iconset
for f in *_2x.png; do mv "$f" "${f/_2x/@2x}"; done

# 3. Build .icns
cd ..
iconutil -c icns ClearanceKit.iconset
```

This produces `ClearanceKit.icns`.

## File mapping

| Filename here | macOS name | Pixel size |
|---|---|---|
| `icon_16x16.png` | `icon_16x16.png` | 16×16 |
| `icon_16x16_2x.png` | `icon_16x16@2x.png` | 32×32 |
| `icon_32x32.png` | `icon_32x32.png` | 32×32 |
| `icon_32x32_2x.png` | `icon_32x32@2x.png` | 64×64 |
| `icon_128x128.png` | `icon_128x128.png` | 128×128 |
| `icon_128x128_2x.png` | `icon_128x128@2x.png` | 256×256 |
| `icon_256x256.png` | `icon_256x256.png` | 256×256 |
| `icon_256x256_2x.png` | `icon_256x256@2x.png` | 512×512 |
| `icon_512x512.png` | `icon_512x512.png` | 512×512 |
| `icon_512x512_2x.png` | `icon_512x512@2x.png` | 1024×1024 |

## Notes

- Background: `#F4F1EA` (warm off-white)
- Letterform: `#0E1014` (near-black)
- Check accent: `#E8893A` (warm signal orange)
- Shield silhouette: `#0E1014` at 6% opacity
- Squircle: Apple superellipse, n=5
