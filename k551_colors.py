"""
k551_color.py - control the lighting on a Redragon K551RGB from the command line.

Protocol reverse-engineered from Redragon's own "K551RGB-1 V2" software
(EVision VS11K28A controller). The script only sends commands that software
sends, writing the same fields in the same way.

Requires:  pip install hidapi

Examples:
    python k551_color.py                          # solid red (same as before)
    python k551_color.py --color 00FF80           # solid other color
    python k551_color.py --modes                  # list the lighting modes
    python k551_color.py --show                   # print current settings
    python k551_color.py --mode breathing --color FF0000 --speed 2
    python k551_color.py --mode wave --colorful   # rainbow version of a mode
    python k551_color.py --brightness 4           # change only brightness
    python k551_color.py --mode ripple --direction reverse
    python k551_color.py --list                   # check the keyboard is found
    add --dry-run to any command to see the packets without sending them

Settings are saved on the keyboard itself.
"""
import argparse
import sys
import time

try:
    import hid
except ImportError:
    sys.exit("Missing module: run  pip install hidapi")

# ---- device -----------------------------------------------------------------
SUPPORTED_IDS = [(0x0C45, 0x5004), (0x320F, 0x5000)]
USAGE_PAGE = 0xFF1C
USAGE = 0x92

REPORT_ID = 0x04
PACKET_LEN = 64

CMD_BEGIN = 0x01
CMD_END = 0x02
CMD_READ_CONFIG = 0x03
CMD_READ_PROFILE = 0x05
CMD_WRITE_PROFILE = 0x06

CONFIG_LEN = 0x2C
CONFIG_PROFILE_INDEX = 0x0A
PROFILE_STRIDE = 0x2A

# ---- per-profile lighting fields ---------------------------------------------
OFF_MODE = 0x00
OFF_BRIGHTNESS = 0x01     # 0..4 (4 = brightest)
OFF_SPEED = 0x02          # 0..4 (0 = fastest, as stored by the app)
OFF_DIRECTION = 0x03      # 0x00 or 0xFF
OFF_COLORFUL = 0x04       # 1 = rainbow / random colors, 0 = single color
OFF_COLOR = 0x05          # R, G, B

DIRECTIONS = {"normal": 0x00, "reverse": 0xFF}

# Mode numbers and the names the Redragon app shows (English language file),
# plus short aliases. "color" = the app offers a single color / colorful toggle.
MODES = [
    # num, app name,                 aliases,                          color
    (1,  "Go with the stream",       ["stream", "wave"],               True),
    (2,  "Clouds fly",               ["clouds"],                       True),
    (3,  "Winding paths",            ["winding"],                      True),
    (4,  "The trial of light",       ["trial"],                        False),
    (5,  "Breathing",                ["breathing", "breath"],          True),
    (6,  "Normally on",              ["static", "solid", "on"],        True),
    (7,  "Pass without trace",       ["reactive", "pass"],             True),
    (8,  "Ripple graff",             ["ripple"],                       False),
    (9,  "Fast run without trace",   ["fastrun"],                      False),
    (10, "Snow winter jasmine",      ["snow"],                         False),
    (11, "Flowers blooming",         ["flowers"],                      False),
    (12, "Swift action",             ["swift"],                        False),
    (13, "Hurricane",                ["hurricane"],                    True),
    (14, "Accumulate",               ["accumulate"],                   True),
    (15, "Digital Times",            ["digital"],                      True),
    (16, "Both ways",                ["bothways"],                     False),
    (17, "Surmount",                 ["surmount"],                     False),
    (18, "Fast and the Furious",     ["furious"],                      False),
    (20, "Coastal",                  ["coastal"],                      False),
]


def mode_name(num):
    for n, name, _, _ in MODES:
        if n == num:
            return name
    return f"unknown ({num})"


def parse_mode(text):
    t = text.strip().lower().replace(" ", "")
    for n, name, aliases, _ in MODES:
        if t == str(n) or t == name.lower().replace(" ", "") or t in aliases:
            return n
    raise argparse.ArgumentTypeError(f"unknown mode '{text}' (see --modes)")


def parse_color(text):
    text = text.lstrip("#")
    if len(text) != 6:
        raise argparse.ArgumentTypeError("use 6 hex digits, e.g. FF0000")
    return bytes.fromhex(text)


def level(text):
    v = int(text)
    if not 0 <= v <= 4:
        raise argparse.ArgumentTypeError("must be 0-4")
    return v


# ---- protocol -----------------------------------------------------------------
def build_packet(cmd, length=0, offset=0, data=b""):
    pkt = bytearray(PACKET_LEN)
    pkt[0] = REPORT_ID
    pkt[3] = cmd
    pkt[4] = length & 0xFF
    pkt[5] = offset & 0xFF
    pkt[6] = (offset >> 8) & 0xFF
    pkt[8:8 + len(data)] = data
    checksum = sum(pkt[3:]) & 0xFFFF
    pkt[1] = checksum & 0xFF
    pkt[2] = checksum >> 8
    return bytes(pkt)


def find_device():
    for vid, pid in SUPPORTED_IDS:
        for info in hid.enumerate(vid, pid):
            if info.get("usage_page") == USAGE_PAGE and info.get("usage") == USAGE:
                return info
    return None


class Keyboard:
    def __init__(self, info, dry_run=False, verbose=True):
        self.dry_run = dry_run
        self.verbose = verbose
        self.dev = None
        if not dry_run:
            self.dev = hid.device()
            self.dev.open_path(info["path"])

    def close(self):
        if self.dev:
            self.dev.close()

    def transact(self, pkt, label):
        if self.verbose:
            print(f"  {label:<22} {pkt[:16].hex(' ')} ...")
        if self.dry_run:
            return None
        # The keyboard sometimes sends an extra copy of a reply late. Throw away
        # anything left over from earlier commands before sending this one.
        while self.dev.read(PACKET_LEN, 20):
            pass
        self.dev.write(pkt)

        replies = []
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline:
            wait = 1000 if not replies else 60   # after a match, briefly collect duplicates
            raw = bytes(self.dev.read(PACKET_LEN, wait))
            if not raw:
                if replies:
                    break
                continue
            if raw[0] != REPORT_ID:      # some hidapi builds drop the report ID
                raw = bytes([REPORT_ID]) + raw
            if raw[3] == pkt[3]:
                replies.append(raw)
            # replies for other commands are stale leftovers: ignore them
        if not replies:
            raise RuntimeError(f"No reply to {label}; stopping.")
        # Prefer a reply that carries data over a plain echo of our packet.
        reply = next((r for r in reversed(replies) if r != pkt), replies[-1])
        if reply[7] in (0xFE, 0xFF):
            raise RuntimeError(f"Keyboard rejected {label} (status {reply[7]:#04x}).")
        return reply

    def begin(self):
        self.transact(build_packet(CMD_BEGIN), "begin")

    def end(self):
        time.sleep(0.01)
        self.transact(build_packet(CMD_END), "end")

    def active_profile(self):
        if self.dry_run:
            return 0
        self.begin()
        reply = self.transact(build_packet(CMD_READ_CONFIG, CONFIG_LEN), "read config")
        self.end()
        profile = reply[8 + CONFIG_PROFILE_INDEX]
        if profile > 2:
            raise RuntimeError(f"Odd profile index {profile}; stopping without writing.")
        return profile

    def read_profile(self, profile):
        self.begin()
        reply = self.transact(build_packet(CMD_READ_PROFILE, 0x38, profile * PROFILE_STRIDE),
                              "read profile")
        self.end()
        return None if reply is None else reply[8:8 + PROFILE_STRIDE]

    def write_fields(self, base, fields):
        """fields: list of (offset, bytes, label); sent as one begin/end batch."""
        self.begin()
        for off, data, label in fields:
            self.transact(build_packet(CMD_WRITE_PROFILE, len(data), base + off, bytes(data)), label)
        self.end()


# ---- main -----------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Redragon K551RGB lighting control.")
    ap.add_argument("--mode", type=parse_mode, help="lighting mode (name, alias or number)")
    ap.add_argument("--color", type=parse_color, help="single color RRGGBB (turns off colorful)")
    ap.add_argument("--colorful", action="store_true", help="use rainbow/random colors")
    ap.add_argument("--brightness", type=level, help="0-4 (4 = brightest)")
    ap.add_argument("--speed", type=level, help="0-4 (0 = fastest)")
    ap.add_argument("--direction", choices=DIRECTIONS, help="effect direction")
    ap.add_argument("--show", action="store_true", help="print current settings")
    ap.add_argument("--modes", action="store_true", help="list lighting modes")
    ap.add_argument("--list", action="store_true", help="list matching devices")
    ap.add_argument("--dry-run", action="store_true", help="print packets, send nothing")
    args = ap.parse_args()

    if args.modes:
        print(" #  name                      aliases                color option")
        for n, name, aliases, color in MODES:
            print(f"{n:2}  {name:<25} {', '.join(aliases):<22} {'yes' if color else '-'}")
        return

    if args.color and args.colorful:
        ap.error("use either --color or --colorful, not both")

    info = find_device()
    if args.list:
        print("0C45 / 320F HID interfaces found:")
        for vid, _ in SUPPORTED_IDS:
            for i in hid.enumerate(vid, 0):
                print(f"  {i['vendor_id']:04X}:{i['product_id']:04X} "
                      f"usage {i['usage_page']:04X}:{i['usage']:04X}  {i.get('product_string')}")
        print("Compatible lighting interface:", "FOUND" if info else "not found")
        return

    if info is None and not args.dry_run:
        sys.exit("No compatible keyboard found (needs USB 0C45:5004 or 320F:5000, interface "
                 "FF1C:0092). Nothing was sent. Run with --list to see what is connected.")

    nothing_requested = not any([args.mode, args.color, args.colorful, args.brightness is not None,
                                 args.speed is not None, args.direction, args.show])
    if nothing_requested:                      # default: solid red, as before
        args.mode = 6
        args.color = bytes.fromhex("FF0000")

    kb = Keyboard(info, dry_run=args.dry_run, verbose=not args.show or args.dry_run)
    try:
        profile = kb.active_profile()
        base = profile * PROFILE_STRIDE

        if args.show:
            p = kb.read_profile(profile)
            if p is None:
                print("(dry run: nothing read)")
                return
            r, g, b = p[OFF_COLOR:OFF_COLOR + 3]
            print(f"Profile {profile}")
            print(f"  mode       {p[OFF_MODE]}  ({mode_name(p[OFF_MODE])})")
            print(f"  brightness {p[OFF_BRIGHTNESS]}  (0-4)")
            print(f"  speed      {p[OFF_SPEED]}  (0 = fastest)")
            print(f"  direction  {'reverse' if p[OFF_DIRECTION] == 0xFF else 'normal'}")
            print(f"  colors     {'colorful' if p[OFF_COLORFUL] else f'single #{r:02X}{g:02X}{b:02X}'}")
            return

        print(f"Profile {profile}" + ("  [dry run]" if args.dry_run else ""))
        # Same grouping the official app uses: each setting is its own begin/end batch.
        if args.mode is not None:
            print(f"Mode: {mode_name(args.mode)}")
            kb.write_fields(base, [(OFF_MODE, [args.mode], "mode")])
        if args.color is not None:
            r, g, b = args.color
            print(f"Color: #{r:02X}{g:02X}{b:02X}")
            kb.write_fields(base, [(OFF_COLORFUL, [0], "single color"),
                                   (OFF_COLOR, [r, g, b], "color")])
        elif args.colorful:
            print("Color: colorful")
            kb.write_fields(base, [(OFF_COLORFUL, [1], "colorful")])
        if args.brightness is not None:
            print(f"Brightness: {args.brightness}")
            kb.write_fields(base, [(OFF_BRIGHTNESS, [args.brightness], "brightness")])
        if args.speed is not None:
            print(f"Speed: {args.speed}")
            kb.write_fields(base, [(OFF_SPEED, [args.speed], "speed")])
        if args.direction:
            print(f"Direction: {args.direction}")
            kb.write_fields(base, [(OFF_DIRECTION, [DIRECTIONS[args.direction]], "direction")])
    finally:
        kb.close()
    print("Done.")


if __name__ == "__main__":
    main()
