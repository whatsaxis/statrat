from __future__ import annotations

import json

from enum import Enum

from statrat.core.proxy import Proxy
from statrat.net.packet import InboundEnum, State
from statrat.net.field import String, Byte


class ChatType:

    class Inbound(InboundEnum):

        SystemChatMessage = (
            0x02,
            State.Play,
            (
                ('message', String()),
                ('type', Byte())
            )
        )


class Component:

    def __init__(self, *components):
        if not components:
            self.components = []
        else:
            self.components = list(components)

    def __add__(self, other: dict | 'Component'):
        # Note that __radd__() is not implemented on purpose

        if isinstance(other, dict):
            self.components.append(other)
        else:
            self.components += other.components

        return self

    def build(self):
        if len(self.components) == 1:
            return json.dumps(self.components[0])

        base = self.components[0]
        rest = self.components[1:]

        base['extra'] = rest

        return json.dumps(base)


STYLE_CHAR = '§'


class Color(Enum):
    Black = ('black', '0')
    DarkBlue = ('dark_blue', '1')
    DarkGreen = ('dark_green', '2')
    DarkAqua = ('dark_aqua', '3')
    DarkRed = ('dark_red', '4')
    Purple = ('dark_purple', '5')
    Gold = ('gold', '6')
    Gray = ('gray', '7')
    DarkGray = ('dark_gray', '8')
    Blue = ('blue', '9')
    Green = ('green', 'a')
    Aqua = ('aqua', 'b')
    Red = ('red', 'c')
    Pink = ('light_purple', 'd')
    Yellow = ('yellow', 'e')
    White = ('white', 'f')


class Style(Enum):
    Obfuscated = 'k'
    Bold = 'l'
    Strikethrough = 'm'
    Underlined = 'n'
    Italic = 'o'
    Reset = 'r'


def comp(
        msg: str,

        *,

        color: Color = None,
        bold=False,
        italic=False,
        underlined=False,
        strikethrough=False,
        obfuscated=False
):
    """Creates a text component."""

    if color is None:
        color = Color.White

    return Component({
        'text': msg,
        'color': color.value[0],

        'bold': bold,
        'italic': italic,
        'underlined': underlined,
        'strikethrough': strikethrough,
        'obfuscated': obfuscated
    })


def text(
        msg: str,

        *styles: Style,

        color: Color = None
):
    """Creates a color coded text string."""

    reset = STYLE_CHAR + Style.Reset.value
    color = STYLE_CHAR + color.value[1]
    styles = ''.join(STYLE_CHAR + s.value for s in styles)

    # RESET added as a suffix to not mess up mod messages
    return reset + color + styles + msg + reset


def send_message(proxy: Proxy, msg: str | Component):
    if isinstance(msg, Component):
        msg = msg.build()

    packet = proxy.create_packet(ChatType.Inbound.SystemChatMessage)

    packet.write_field('message', msg)
    packet.write_field('type', 0)

    proxy.send_client(packet)
