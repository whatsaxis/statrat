from statrat.core.proxy import Proxy
from statrat.core.logging import info

from statrat.net.field import VarInt
from statrat.net.packet import Packet, OutboundEnum, State

p = Proxy()


class CustomType:

    class Outbound(OutboundEnum):
        SwingArm = (
            0x0a,
            State.Play,
            (
                ('hand', VarInt()),
            )
        )


@p.listen(CustomType.Outbound.SwingArm)
def swing_listener(packet: Packet):
    info(f'Player swung their arm! [hand={ packet.get_fields("hand") }]')

    return True


p.start()
