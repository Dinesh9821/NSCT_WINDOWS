"""
core/iconkit.py
Icon registry supporting two kinds of icons:

  • qtawesome glyphs (recolored on theme toggle) — pass a Font Awesome name:
        iconkit.button(btn, "fa5s.play", role="ON_ACCENT", size=16)

  • custom image tiles from assets/icons/<key>.png — pass "img:<key>":
        iconkit.button(btn, "img:dashboard", size=22)
    Image tiles are full-color and do NOT recolor with the theme.

Missing image files fall back to a neutral qtawesome glyph so the app never
breaks if an asset is absent.
"""

import os
import qtawesome as qta
from PySide6.QtCore import QSize, Qt
from PySide6.QtGui import QIcon, QPixmap

from core.theme import theme

_ICON_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "assets", "icons")
_PIXMAP_CACHE = {}
_entries = []  # each: [kind, target, name/key, role, size]


# --------------------------------------------------------------------------- #
#  helpers
# --------------------------------------------------------------------------- #
def _is_img(name):
    return isinstance(name, str) and name.startswith("img:")


def _color(role):
    try:
        return theme.c(role)
    except KeyError:
        return theme.c("TEXT_SECONDARY")


def _img_path(key):
    return os.path.join(_ICON_DIR, key + ".png")


def _img_pixmap(key, size):
    ck = (key, size)
    if ck in _PIXMAP_CACHE:
        return _PIXMAP_CACHE[ck]
    path = _img_path(key)
    pm = QPixmap(path)
    if pm.isNull():
        pm = qta.icon("fa5s.cube", color=theme.c("ACCENT")).pixmap(size, size)
    else:
        pm = pm.scaled(size, size, Qt.KeepAspectRatio, Qt.SmoothTransformation)
    _PIXMAP_CACHE[ck] = pm
    return pm


def _img_icon(key, size):
    return QIcon(_img_pixmap(key, size))


# --------------------------------------------------------------------------- #
#  apply
# --------------------------------------------------------------------------- #
def _apply(entry):
    kind, target, name, role, size = entry
    if kind == "imgbutton":
        target.setIcon(_img_icon(name, size))
        target.setIconSize(QSize(size, size))
    elif kind == "imglabel":
        target.setPixmap(_img_pixmap(name, size))
    elif kind == "button":
        target.setIcon(qta.icon(name, color=_color(role)))
        target.setIconSize(QSize(size, size))
    else:  # label
        target.setPixmap(qta.icon(name, color=_color(role)).pixmap(size, size))


def button(btn, name, role="TEXT_SECONDARY", size=18):
    kind = "imgbutton" if _is_img(name) else "button"
    key = name[4:] if _is_img(name) else name
    entry = [kind, btn, key, role, size]
    _entries.append(entry)
    _apply(entry)
    return btn


def label(lbl, name, role="TEXT_SECONDARY", size=18):
    kind = "imglabel" if _is_img(name) else "label"
    key = name[4:] if _is_img(name) else name
    entry = [kind, lbl, key, role, size]
    _entries.append(entry)
    _apply(entry)
    return lbl


def set_role(target, role):
    for entry in _entries:
        if entry[1] is target:
            if entry[0] in ("imgbutton", "imglabel"):
                return  # image tiles can't be recolored
            entry[3] = role
            _apply(entry)


def refresh():
    for entry in list(_entries):
        if entry[0] in ("imgbutton", "imglabel"):
            continue  # image tiles are theme-independent
        try:
            _apply(entry)
        except Exception:
            pass


# Recolor qtawesome glyphs whenever the palette changes.
theme.changed.connect(refresh)
