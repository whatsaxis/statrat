import requests
from statrat.auth.session import get_uuid
from chat import comp, text, Color, Style
import json
# import cloudscraper
#
#
# cs = cloudscraper.create_scraper()


key = '08ec7b66-8e7c-4243-9557-75ced5300ed8'


stats_cache = {}


def get_data(username: str):
    """Fetch the data for a user."""

    if username in stats_cache:
        return stats_cache[username]

    stats_cache[username] = requests.get(f'https://api.hypixel.net/player?uuid={ get_uuid(username) }', headers={'Api-Key': key}).json()
    return stats_cache[username]

    # with open('a.json', 'r') as f:
    #     return json.loads(f.read())


def format_rank(data: dict):
    data = data['player']

    username = data['playername']

    rank = data.get('newPackageRank', None)
    plus_color = data.get('rankPlusColor', None)

    if plus_color is not None:
        for c in Color:
            if c.value[0] == plus_color.lower():
                plus_color = c
                break

    if rank is None:
        return comp(username, color=Color.Gray)

    if rank == 'VIP':
        return (
                comp('[VIP] ', color=Color.Green) +
                comp(username, color=Color.Green)
        )

    if rank == 'VIP_PLUS':
        return (
                comp('[VIP', color=Color.Green) +
                comp('+', color=Color.Gold) +
                comp('] ', color=Color.Green) +
                comp(username, color=Color.Green)
        )

    if rank == 'MVP':
        return (
                comp('[MVP] ', color=Color.Aqua) +
                comp(username, color=Color.Aqua)
        )

    if rank == 'MVP_PLUS':
        return (
                comp('[MVP', color=Color.Aqua) +
                comp('+', color=plus_color) +
                comp('] ', color=Color.Aqua) +
                comp(username, color=Color.Aqua)
        )

    if rank == 'MVP_PLUS_PLUS':
        return (
                comp('[MVP', color=Color.Gold) +
                comp('+', color=plus_color) +
                comp('] ', color=Color.Gold) +
                comp(username, color=Color.Gold)
        )

# Starting at 100 wins, a division is assigned
# Below are the division names, their win intervals, and colors


DUELS_DIVISIONS = (
    ('Rookie', 20, Color.DarkGray, None),
    ('Iron', 60, Color.White, None),
    ('Gold', 100, Color.Gold, None),
    ('Diamond', 200, Color.DarkAqua, None),
    ('Master', 400, Color.DarkGreen, None),
    ('Legend', 1200, Color.DarkRed, Style.Bold),
    ('Grandmaster', 2000, Color.Yellow, Style.Bold),
    ('Godlike', 6000, Color.Purple, Style.Bold),
    ('Celestial', 10_000, Color.Aqua, Style.Bold),
    ('Divine', 20_000, Color.Pink, Style.Bold),
    ('Ascended', 20_000, Color.Red, Style.Bold)
)

BW_PRESTIGES = (
    Color.Gray,
    Color.White,
    Color.Gold,
    Color.Aqua,
    Color.DarkGreen,
    Color.DarkAqua,
    Color.DarkRed,
    Color.Pink,
    Color.DarkBlue,
    Color.Purple
)

RAINBOW = (
    Color.Red,
    Color.Gold,
    Color.Yellow,
    Color.Green,
    Color.Aqua,
    Color.Pink,
    Color.Purple
)

ROMAN_MAP = [(1000, 'M'), (900, 'CM'), (500, 'D'), (400, 'CD'), (100, 'C'), (90, 'XC'),
             (50, 'L'), (40, 'XL'), (10, 'X'), (9, 'IX'), (5, 'V'), (4, 'IV'), (1, 'I')]


def num2roman(num):

    # Thanks, StackOverflow.

    roman = ''

    while num > 0:
        for i, r in ROMAN_MAP:
            while num >= i:
                roman += r
                num -= i

    return roman


def format_duels_division(wins: int):
    if wins < 100:
        return comp('✫', color=Color.Gold)

    wins_needed = 100

    for i, division in enumerate(DUELS_DIVISIONS):
        name, wins_per_lvl, color, style = division

        title_lvl = (wins - wins_needed) // wins_per_lvl + 1
        roman = num2roman(title_lvl)

        # Within division bracket or surpassing Ascended (why..)
        if wins < wins_needed + wins_per_lvl * 5 or i == len(DUELS_DIVISIONS) - 1:
            if style is not None:
                formatted = text(name, style, color=color) + ((' ' + text(roman, style, color=color)) if title_lvl > 1 else '')
            else:
                formatted = text(name, color=color) + ((' ' + text(roman, color=color)) if title_lvl > 1 else '')

            return comp('✫ ', color=Color.Gold) + comp(formatted)

        wins_needed += 5 * wins_per_lvl


def format_bw_star(star: int):
    if star >= 1000:
        star = str(star)

        o = comp('[', color=RAINBOW[0])
        for i, c in enumerate(star):
            o += comp(c, color=RAINBOW[(i + 1) % len(RAINBOW)])

        o += comp('✫', color=RAINBOW[len(o.components) % len(RAINBOW)])
        o += comp(']', color=RAINBOW[(len(o.components) + 1) % len(RAINBOW)])

        return o

    for i, color in enumerate(BW_PRESTIGES):
        if star < (i + 1) * 100:
            return comp(f'[{ star }✫]', color=color)


def get_duels_stats(data: dict):
    data_d = data['player']['stats'].get('Duels', {'wins': 0, 'losses': 0})

    wins = data_d.get('wins', 0)

    # Let's avoid division by 0!
    losses = data_d.get('losses', 1)

    return {
        'wins': wins,
        'losses': losses,
        'wlr': round(wins / losses, 2),
        'formatted': format_duels_division(wins) + comp(' ') + format_rank(data)
    }


def get_bw_stats(data: dict):
    data_d = data['player']['stats'].get('Bedwars', {
        'final_kills_bedwars': 0,
        'final_deaths_bedwars': 1,
        'wins_bedwars': 0,
        'losses_bedwars': 1
    })

    star = data['player']['achievements'].get('bedwars_level', 1)

    final_kills = data_d.get('final_kills_bedwars', 0)
    final_deaths = data_d.get('final_deaths_bedwars', 1)

    wins = data_d.get('wins_bedwars', 0)
    losses = data_d.get('losses_bedwars', 1)

    return {
        'wins': wins,
        'losses': losses,
        'final_kills': final_kills,
        'final_deaths': final_deaths,

        'wlr': round(wins / losses, 2),
        'fkdr': round(final_kills / final_deaths, 2),

        'formatted': format_bw_star(star) + comp(' ') + format_rank(data)
    }


def get_sw_stats(data: dict):
    data_d = data['player']['stats'].get('SkyWars', {
        'wins': 0,
        'losses': 1,
        'kills': 0,
        'deaths': 1,
        'levelFormattedWithBrackets': '§7[1⋆]'
    })

    wins = data_d.get('wins', 0)
    losses = data_d.get('losses', 1)

    kills = data_d.get('kills', 0)
    deaths = data_d.get('deaths', 1)

    formatted = data_d.get('levelFormattedWithBrackets', '§7[1⋆]')

    return {
        'wins': wins,
        'losses': losses,

        'kills': kills,
        'deaths': deaths,

        'kdr': round(kills / deaths, 2),
        'wlr': round(wins / losses, 2),

        'formatted': comp(formatted) + comp(' ') + format_rank(data)
    }
