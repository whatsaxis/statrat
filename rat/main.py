import json
import re
from collections import defaultdict

from statrat.core.proxy import Proxy
from statrat.net.compress import Compression
from statrat.net.packet import Packet, PacketRaw, PacketHandler, State, InboundEnum, OutboundEnum
from statrat.auth.session import get_uuid
from statrat.net.field import *

from chat import Color, comp, text, Style, send_message
from stats import get_bw_stats, get_duels_stats, get_data, get_sw_stats, stats_cache

p = Proxy()

'''
Known packets:

Swing arm: 0x0a
Player position: 0x04
Set head rotation: 0x05
Chat message: 0x02
Update teams: 0x3e
Boss bar: 0x1c
'''


def is_valid_username(s: str):
    return all(
        c.isnumeric() or c.isalpha() or c == '_'
        for c in s
    )


class PacketType:

    class Inbound(InboundEnum):
        SystemChatMessage = (
            0x02,
            State.Play,
            (
                ('message', String()),
                ('type', Byte())
            )
        )

        UpdateTeams = (
            0x3e,
            State.Play,
            tuple()
        )

        EntityMetadata = (
            0x1c,
            State.Play,
            tuple()
        )

        UpdateTeamInfo = (
            0x3e,
            State.Play,
            (
                ('team_name', String()),
                ('mode', Byte()),
                ('team_display_name', String()),
                ('team_prefix', String()),
                ('team_suffix', String()),
                ('friendly_flags', Byte()),
                ('name_tag_visibility', String()),
                ('color', Byte())
            )
        )

        PlayerInfoUpdateAddPlayer = (
            0x38,
            State.Play,
            (
                ('action', VarInt()),
                ('players', Array(Container(
                    ('uuid', UUID()),
                    ('username', String()),
                    ('properties', Array(
                        Container(
                            ('name', String()),
                            ('value', String()),
                            ('signature', Optional(String()))
                        )
                    )),
                    ('game_mode', VarInt()),
                    ('ping', VarInt()),
                    ('display_name', Optional(String()))
                )))
            )
        )

        Respawn = (
            0x07,
            State.Play,
            tuple()
        )

    class Outbound(OutboundEnum):
        ChatMessage = (
            0x01,
            State.Play,
            (
                ('message', String()),
            )
        )


player_infos = {}

team_id_map = {}
team_id_styles = defaultdict(lambda: ('§7', '', 3, 'always', 15))

'''
PacketRaw[id=1c, size=112, data=aef6ffff0f...]
b'q\x00\x1c\xae\xf6\xff\xff\x0fT\x00\x00\x03\xe8\x82J\xc2\xa76\xc2\xa7lHALLOWEEN BED WARS AND SKYWARS MAPS - MURDER MYSTERY DARKFALL REVAMPS \x00\x00\x00\x00\x00 Q\x00\x00\x00\x00R\x00\x00\x00\x00 \x03 \x01fC\x96\x00\x00\x7f'
'''


def read_metadata(buff: Buffer):
    metadata = {}

    while True:
        i = buff.read(UnsignedByte())

        if i == 127:
            break

        field_type, key = i >> 5, i & 0x1F
        field = None

        if field_type == 0:
            field = Byte()
        elif field_type == 1:
            field = Short()
        elif field_type == 2:
            field = Int()
        elif field_type == 3:
            field = Float()
        elif field_type == 4:
            field = String()

        # ItemStacks, Positions, and Rotations aren't important for us

        elif field_type == 5:
            if buff.read(Short()) >= 0:
                buff.read(Byte())
                buff.read(Short())

            field = None
        elif field_type == 6:
            buff.read(Int())
            buff.read(Int())
            buff.read(Int())

            field = None
        elif field_type == 7:
            buff.read(Float())
            buff.read(Float())
            buff.read(Float())

            field = None
        else:
            # TODO Handle this
            pass

        if field is not None:
            metadata[key] = buff.read(field)

    return metadata


players = []
current_mode = 'LOBBY'

counter = 0

game_match = re.compile(r'Playing (.*) on')


def stat_check(username: str, mode: str):
    try:
        if mode.upper() == 'DUELS':
            stats = get_duels_stats(get_data(username))
            stats_display = comp('W: ') + comp(stats['wins'], color=Color.Yellow) + comp(' W/L: ') + comp(stats['wlr'],
                                                                                                          color=Color.Yellow)
        elif mode.upper() in {'BEDWARS', 'BW'}:
            stats = get_bw_stats(get_data(username))
            stats_display = comp('W: ') + comp(stats['wins'], color=Color.Yellow) + comp(' F: ') + comp(
                stats['final_kills'], color=Color.Yellow) + comp(' W/L: ') + comp(
                stats['wlr'], color=Color.Yellow) + comp(' FKDR: ') + comp(
                stats['fkdr'], color=Color.Yellow)
        elif mode.upper() in {'SKYWARS', 'SW'}:
            stats = get_sw_stats(get_data(username))
            stats_display = comp('W: ') + comp(stats['wins'], color=Color.Yellow) + comp(' K: ') + comp(
                stats['kills'], color=Color.Yellow) + comp(' W/L: ') + comp(
                stats['wlr'], color=Color.Yellow) + comp(' KDR: ') + comp(
                stats['kdr'], color=Color.Yellow)
        else:
            send_message(
                p,
                comp('▌ ', color=Color.Red) + comp(f'Unsupported gamemode! ({mode})')
            )

            return None

        send_message(
            p,
            comp('▌ ', color=Color.Blue) + stats['formatted'] + comp(' | ', color=Color.Yellow) + stats_display
        )

        return stats

    except Exception as e:
        send_message(
            p,
            comp('▌ ', color=Color.Red) + comp(username, color=Color.Gray) + comp(' | ', color=Color.Yellow) + comp(
                'ERROR', color=Color.Red)
        )

        import traceback
        traceback.print_exc()


def on_player_join(username: str):
    # !
    # Chat Stats
    # !

    stats = stat_check(username, current_mode)

    # !
    # Tab list
    # !

    if current_mode == 'DUELS' or stats is None:
        return

    pa = p.create_packet(PacketType.Inbound.PlayerInfoUpdateAddPlayer)
    pa.write_field('action', 0)

    print(player_infos.keys())


@p.listen(PacketType.Outbound.ChatMessage)
def on_player_chat_message(packet: Packet):
    msg = packet.get_fields('message')

    if msg.startswith('/sc'):
        if len(msg.split(' ')) != 3:
            send_message(
                p,
                comp('▌ ', color=Color.Red) + comp(f'Invalid arguments! ') + comp('/sc [bedwars/skywars/duels] [username]', color=Color.Yellow)
            )

            return True

        mode, username = msg.split(' ')[1:]

        if mode.lower() == 'all':
            stat_check(username, 'BEDWARS')
            stat_check(username, 'SKYWARS')
            stat_check(username, 'DUELS')

        return False

    return True


@p.listen(PacketType.Inbound.Respawn, raw=True)
def on_respawn(packet_raw: PacketRaw):
    global players, player_infos, current_mode, counter

    # The Respawn packet (0x07) is how the BungeeCord proxy changes the server of a player.
    current_mode = '?'

    players = []
    player_infos = {}

    counter = 0

    return True


@p.listen(PacketType.Inbound.EntityMetadata, raw=True)
def on_entity_metadata(packet_raw: PacketRaw):
    global current_mode, players

    try:
        packet_raw.data.read(VarInt())
        meta = read_metadata(packet_raw.data)

        string_data: str = meta.get(2, None)

        # Differentiates between BossBar and other entity metas
        if not string_data or meta.get(20, None) != 1000:
            return True

        string_data = re.sub(r'§.', '', string_data)
        mode = re.match(game_match, string_data)

        if mode:
            if mode.group(1) == current_mode:
                return True

            mode = mode.group(1)
            send_message(p, comp('▌ ', color=Color.Green) + comp('You are now playing ') + comp(mode, color=Color.Yellow))
            current_mode = mode

            if current_mode == 'DUELS':
                players = players[1::2]

                send_message(p, comp('▌ ', color=Color.Yellow) + comp('Players in this game: ') + comp(str(players),
                                                                                                       color=Color.Yellow))

                for pl in players:
                    stat_check(pl, 'DUELS')

            # Default
            else:
                send_message(p, comp('▌ ', color=Color.Yellow) + comp('Players in this game: ') + comp(str(players), color=Color.Yellow))

        else:
            if current_mode == 'LOBBY':
                return True

            send_message(p, comp('▌ ', color=Color.Green) + comp('You are now in the ') + comp('LOBBY', color=Color.Yellow))
            current_mode = 'LOBBY'

    except IndexError:
        return True

    return True


@p.listen(PacketType.Inbound.UpdateTeams, raw=True)
def on_update_teams(packet_raw: PacketRaw):
    global players, counter

    buff = packet_raw.data.copy()

    team_id = buff.read(String())
    mode = buff.read(Byte())

    # if mode == 2:
    #     u = p.create_packet(PacketType.Inbound.UpdateTeamInfo, packet_raw)
    #     team_id_styles[team_id] = u.get_fields('team_prefix', 'team_suffix', 'friendly_flags', 'name_tag_visibility', 'color')
    #     print('styles', team_id_styles[team_id])

    # Player information packets are sent before game mode is detected.

    if mode == 3:
        name: str = buff.read(Array(String()))[0]

        if is_valid_username(name) and name not in players:

            # Add player to players set
            players.append(name)

            counter += 1

            # BossBar packet has been sent
            if current_mode != '?' and current_mode != 'LOBBY':
                # For players that join after the user, a counter is used and detects the mode.
                if counter % 2 != 0 and current_mode == 'DUELS':
                    return True

                on_player_join(name)

            # team_prefix, team_suffix, friendly_flags, name_tag_visibility, color = team_id_styles[team_id]
            # team_id_map[name] = team_id

            # import random
            #
            # pa = p.create_packet(PacketType.Inbound.PlayerInfoUpdateAddPlayer)
            # pa.write_field('action', 0)
            #
            # if not in_game:
            #     uuid, username, properties, game_mode, ping, display_name = player_infos[name]
            #
            #     pa.write_field('players', (
            #         (
            #             uuid,
            #             username,
            #             # TODO LOL show buv
            #             (('textures', 'ewogICJ0aW1lc3RhbXAiIDogMTY5NzU3Nzk5MzgxOSwKICAicHJvZmlsZUlkIiA6ICIyMGUwZTNhYzNlN2I0NGQwYmFhMTUxOTgxOTAxMjNmOCIsCiAgInByb2ZpbGVOYW1lIiA6ICJ3aGF0c2F4aXMiLAogICJzaWduYXR1cmVSZXF1aXJlZCIgOiB0cnVlLAogICJ0ZXh0dXJlcyIgOiB7CiAgICAiU0tJTiIgOiB7CiAgICAgICJ1cmwiIDogImh0dHA6Ly90ZXh0dXJlcy5taW5lY3JhZnQubmV0L3RleHR1cmUvNzU0ZmEwZDkwZGQwY2I3MDMzNGYwNzJiMWU5OTk2OWM0OTdmZGYyODVmMGZlMWRhYzQwNjkxZmM2ZGM3OGFjYiIsCiAgICAgICJtZXRhZGF0YSIgOiB7CiAgICAgICAgIm1vZGVsIiA6ICJzbGltIgogICAgICB9CiAgICB9CiAgfQp9', 'pDroaZ4CSJft5uwQAyELpWsRid5vQeJOXwDPl8oi2oyStKHZWfKVpCTRmfeLa1KhZYQ754mcAw3u5D7y4xIAS0Ia1gaERioRzKnUUcM2bgHv+EJ2zxzhA6MYK1n74PepfFMsswmN3x2yhO5mB8UcAwiOUtRMoX3dYfXNXebHuBxSBOyrP4ouyGIauSr4GKfOEFzh1GCciZppL7z89/cueKj89n3vfbQz2MBVCV/iOLRxOGdUampmqI8rvxT6gL6e+5ivlfaAQEC2+j9wTKpCTbpDJG58IA7/gqyD1S9d8e1m2NQC3+AqKyMal5PCMAUVG8ly5t9VRKApTlNxIXlZrcMLoMLtI/LcKPvFbIVQ7FeraXGU+r7Oi2y2PNbT2+3TfacOjmtmtHYkj1jJ1h8R1cHYTtzwJgEwr8xJt0p9dgNygW6K/udgvpQNQgPcCQZja658t7tE4B+jt7BY7ufjYoMd733JRXApb6avVsVXuqhI6OoEhJlkKw7/dBFA9OExBJKaJ1UnDyhjhWG4EZl868gygatE2nlv+E52OHWnf64UYc6HE2+gzFznynqZlnzjgHDiolX3ESCE7di5WC4rj2dXMHp0emNu6gccz0C0Theaf7N1tw/oBRqW5x6kYTdBkSknqxUT/SYeNogoFNXoNOTPZfLC+qqFgzT/DrlGLwY='),)
            #             if in_game else properties,
            #             game_mode,
            #             ping,
            #             # TODO WE're gonna have to do prefixes through here.. no biggie though. much better than teams!
            #             # (comp('[200✫] ', color=Color.Gold) + comp(username)).build()
            #             (comp(f'[{ random.randint(1, 99) }✫] ', color=Color.Gray) + comp(team_prefix + name + team_suffix)).build()
            #         ),
            #     ))
            #
            #     p.send_client(pa)

            return True

        return True

    return True


@p.listen(PacketType.Inbound.PlayerInfoUpdateAddPlayer, raw=True)
def on_player_info_update(packet_raw: PacketRaw):
    b = Buffer(packet_raw.data.buffer)

    action = b.read(Byte())

    if action != 0:
        return True

    pa = p.create_packet(PacketType.Inbound.PlayerInfoUpdateAddPlayer, packet_raw)
    # print(pa.get_fields('players'))
    # print('fake', b''.join(pa.fields_byte.values()))
    # print(packet_raw.data.buffer == b''.join(pa.fields_byte.values()))

    uuid, username, properties, game_mode, ping, display_name = pa.get_fields('players')[0]
    player_infos[username] = pa.get_fields('players')[0]

    return True


p.start()
