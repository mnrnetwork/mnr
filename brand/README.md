# mnr brand assets

Mark: two small nodes converge into one large orange node — many upstreams, one endpoint (the relayer).
Drawn on a 24-unit grid; minimum size 16 px. Do not rotate it (horizontal-mirrored it becomes the generic "share" glyph).

| File | Use |
|---|---|
| `mnr-mark.svg` | Default mark on light backgrounds (ink #1B1917, accent #F26822) |
| `mnr-mark-dark.svg` | Mark on dark backgrounds (ink #ECE7E1) |
| `mnr-mark-mono.svg` | One-colour mark (print, embossing, monochrome UIs) |
| `mnr-mark-white.svg` | Reversed on photos or the accent colour |
| `mnr-mark-on-accent.svg` | White inputs, ink centre — for orange surfaces |
| `mnr-lockup.svg`, `mnr-lockup-dark.svg` | Mark + wordmark; wordmark is Geist 700 with fallbacks, text kept live so it stays editable |
| `favicon.svg`, `favicon-32.png`, `favicon-16.png`, `apple-touch-icon.png` | Browser tab / home screen |

Colours: ink #1B1917 · paper #FBFAF8 · accent #F26822 (Monero-orange family; the site's `accent` token) · dark ground #141210.
Clear space: keep at least the radius of the large node free around the mark. Wordmark is always lowercase `mnr`.

## Social preview (`mnr-social-1280.png`)

1280x640, the 2:1 ratio GitHub and X both crop to. Source: `mnr-social-1280.html`,
rendered with

    chrome --headless --force-device-scale-factor=2 --window-size=1280,640 \
      --screenshot=out.png http://127.0.0.1:8000/mnr-social-1280.html
    magick out.png -resize 1280x640 -strip mnr-social-1280.png

Set it under repository Settings, Social preview. Do not upload a 1500x500
banner there: both GitHub and X crop the sides off and cut the wordmark in half.
The bottom ~100px is deliberately empty, because X draws its title pill there.
