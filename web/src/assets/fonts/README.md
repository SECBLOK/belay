# Bundled CJK font — Noto Sans SC (subset)

`NotoSansSC-subset.woff2` is a **subset** of Google's Noto Sans SC **variable**
font (weight axis 100–900), reduced to the ~660 CJK glyphs the UI actually uses
plus basic Latin/punctuation. License: SIL Open Font License 1.1 (see
`NotoSansSC-OFL.txt`) — redistribution/embedding is permitted.

## Why it's bundled
On Windows the system serves Microsoft YaHei and on macOS PingFang SC — both are
good multi-weight CJK families, so the bundled font is NEVER reached there (it
sits AFTER them in the stack, so the browser doesn't even decode it). It exists
only for **Linux**, where the common fallback is WenQuanYi Zen Hei — a SINGLE
weight, so bold headings render thin. This bundle gives Linux a real multi-weight
face so `font-weight` works and the UI stops looking thin. A full system CJK font
and WenQuanYi still follow it in the stack, so any character outside the subset
(dynamic/agent-supplied Chinese) falls through to a real font, never tofu.

## Regenerate (after adding new Chinese UI strings)
Recompute the glyph set from the catalogue and re-subset the variable font:
```
# 1. collect the glyphs the app uses (CJK from the zh-Hans catalogue)
python3 - <<'PY'
s=open('src/locales/zh-Hans.po',encoding='utf8').read()
chars=sorted(set(c for c in s if '一'<=c<='鿿' or c in '，。：；（）、—…“”‘’·【】《》？！'))
open('/tmp/cjk_chars.txt','w',encoding='utf8').write(''.join(chars))
PY
# 2. subset the upstream NotoSansSC[wght].ttf variable font (download from
#    google/fonts ofl/notosanssc), keeping the weight axis:
python3 -m fontTools.subset NotoSansSC[wght].ttf \
  --text-file=/tmp/cjk_chars.txt \
  --unicodes="U+0020-007E,U+00A0-00FF,U+2018-201F,U+2026,U+2014,U+00B7" \
  --flavor=woff2 --layout-features='*' \
  --output-file=src/assets/fonts/NotoSansSC-subset.woff2
```
