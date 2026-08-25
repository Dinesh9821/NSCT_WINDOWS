"""
core/colors.py
Backwards-compatible dynamic proxy. `ThemeColors.ACCENT` (etc.) now returns the
CURRENT theme's value at access time, so QPainter widgets that read it stay
correct across Dark/Light toggles.
"""

from core.theme import theme


class _ThemeColorsMeta(type):
    def __getattr__(cls, name):
        try:
            return theme.c(name)
        except KeyError as e:
            raise AttributeError(name) from e


class ThemeColors(metaclass=_ThemeColorsMeta):
    """Attribute access is resolved live against the active theme palette."""
    pass
