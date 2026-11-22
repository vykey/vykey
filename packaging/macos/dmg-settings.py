# dmgbuild settings for the macOS disk image: a Finder window with the app,
# an arrow and an Applications link to drag it onto (like most Mac apps),
# with the terminal client and docs in a row below.
#
#   dmgbuild -s packaging/macos/dmg-settings.py \
#     -D src=dist/vykey-...-macos-universal -D bg=dmg-background.tiff \
#     "vykey 0.1.1" dist/vykey-...-macos-universal.dmg
#
# `src` holds vykey.app, vy, LICENSE and README.md; `bg` is the background
# (a 1x+2x TIFF from packaging/macos/dmg-background{,@2x}.png).
import os.path

src = defines["src"]  # noqa: F821 (injected by dmgbuild)

format = "UDZO"
filesystem = "HFS+"
files = [os.path.join(src, f) for f in ("vykey.app", "vy", "README.md", "LICENSE")]
symlinks = {"Applications": "/Applications"}
hide_extensions = ["vykey.app"]

background = defines["bg"]  # noqa: F821
window_rect = ((200, 120), (640, 460))
default_view = "icon-view"
show_status_bar = False
show_tab_view = False
show_toolbar = False
show_pathbar = False
show_sidebar = False
icon_size = 96
text_size = 13
icon_locations = {
    "vykey.app": (160, 190),
    "Applications": (480, 190),
    "vy": (200, 370),
    "README.md": (320, 370),
    "LICENSE": (440, 370),
}
