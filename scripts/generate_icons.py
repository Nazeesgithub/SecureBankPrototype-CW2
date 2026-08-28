"""Render the PNG icon fallbacks from the SecureBank shield mark.

Some platforms ignore SVG favicons entirely - iOS home-screen icons are the main
one - so a raster fallback is generated alongside frontend/public/favicon.svg.

    python scripts/generate_icons.py

**Why this draws the shield instead of rasterising the SVG file.** The obvious
approach is cairosvg, but it is a binding to the native Cairo library and there
is no Cairo DLL in a stock Windows Python install:

    OSError: no library called "cairo-2" was found

Installing the GTK runtime just to build one icon is not a reasonable project
dependency, so this script uses Pillow - which installs cleanly everywhere but
cannot parse SVG - and reproduces the same geometry directly. The constants
below are copied from favicon.svg and must be kept in step with it; the shapes
are simple enough (one shield outline, one circle, one trapezoid) that this
stays readable.

Rendering is done at 4x and downsampled, which is what gives the curved shield
edge and the keyhole smooth antialiased edges.
"""

import argparse
import sys
from pathlib import Path

try:
    from PIL import Image, ImageDraw
except ImportError:
    sys.exit(
        "Pillow is required to generate the PNG icons.\n"
        "Install the project dependencies first:  pip install -r requirements.txt"
    )


PROJECT_ROOT = Path(__file__).resolve().parent.parent
PUBLIC_DIR = PROJECT_ROOT / "frontend" / "public"

# --------------------------------------------------------------------------
# Geometry and colour, mirroring frontend/public/favicon.svg
# --------------------------------------------------------------------------
VIEWBOX = 32.0

# linearGradient x1=0 y1=0 x2=1 y2=1 over the shape's bounding box.
GRADIENT_STOPS = [
    (0.00, (0x1B, 0x2A, 0x6B)),  # --brand-deep
    (0.55, (0x12, 0x60, 0x8F)),  # --brand-mid
    (1.00, (0x0F, 0xA3, 0xA3)),  # --brand-accent
]
KEYHOLE_COLOUR = (0xFF, 0xFF, 0xFF)

# Shield outline: M16 2.2 L27.6 6.6 V15.4 C... C... V6.6 Z
SHIELD_APEX = (16.0, 2.2)
SHIELD_TOP_RIGHT = (27.6, 6.6)
SHIELD_RIGHT_WAIST = (27.6, 15.4)
SHIELD_CURVE_RIGHT = ((27.6, 22.5), (22.6, 27.7), (16.0, 29.9))
SHIELD_CURVE_LEFT = ((9.4, 27.7), (4.4, 22.5), (4.4, 15.4))
SHIELD_TOP_LEFT = (4.4, 6.6)

KEYHOLE_CENTRE = (16.0, 13.1)
KEYHOLE_RADIUS = 3.35
KEYHOLE_STEM = [(13.95, 15.6), (18.05, 15.6), (19.15, 22.3), (12.85, 22.3)]

SUPERSAMPLE = 4


def cubic_bezier(start, control_one, control_two, end, steps=64):
    """Flatten one cubic Bezier segment into a list of points."""
    points = []
    for index in range(1, steps + 1):
        t = index / steps
        m = 1.0 - t
        x = (
            m * m * m * start[0]
            + 3 * m * m * t * control_one[0]
            + 3 * m * t * t * control_two[0]
            + t * t * t * end[0]
        )
        y = (
            m * m * m * start[1]
            + 3 * m * m * t * control_one[1]
            + 3 * m * t * t * control_two[1]
            + t * t * t * end[1]
        )
        points.append((x, y))
    return points


def shield_polygon():
    """The shield outline as a flat list of points in 32x32 viewBox units."""
    points = [SHIELD_APEX, SHIELD_TOP_RIGHT, SHIELD_RIGHT_WAIST]

    control_one, control_two, end = SHIELD_CURVE_RIGHT
    points += cubic_bezier(SHIELD_RIGHT_WAIST, control_one, control_two, end)

    control_one, control_two, left_end = SHIELD_CURVE_LEFT
    points += cubic_bezier(end, control_one, control_two, left_end)

    points.append(SHIELD_TOP_LEFT)
    return points


def gradient_colour(t):
    """Interpolate the three gradient stops at position t in [0, 1]."""
    t = min(1.0, max(0.0, t))
    for index in range(len(GRADIENT_STOPS) - 1):
        left_pos, left_rgb = GRADIENT_STOPS[index]
        right_pos, right_rgb = GRADIENT_STOPS[index + 1]
        if left_pos <= t <= right_pos:
            span = right_pos - left_pos
            local = 0.0 if span == 0 else (t - left_pos) / span
            return tuple(
                round(left_rgb[channel] + (right_rgb[channel] - left_rgb[channel]) * local)
                for channel in range(3)
            )
    return GRADIENT_STOPS[-1][1]


def render(size, background):
    """Render the mark at `size` pixels square."""
    work = size * SUPERSAMPLE
    scale = work / VIEWBOX

    polygon = [(x * scale, y * scale) for x, y in shield_polygon()]

    # Bounding box of the shield, which is what the SVG gradient is measured
    # against (objectBoundingBox units are the default for linearGradient).
    xs = [p[0] for p in polygon]
    ys = [p[1] for p in polygon]
    box_x, box_y = min(xs), min(ys)
    box_w, box_h = max(xs) - box_x, max(ys) - box_y

    # Paint the gradient across the bounding box. The gradient runs corner to
    # corner, so a point's position along it is the average of its normalised x
    # and y offsets.
    gradient = Image.new("RGB", (work, work), GRADIENT_STOPS[0][1])
    pixels = gradient.load()
    for y in range(work):
        v = (y - box_y) / box_h if box_h else 0.0
        for x in range(work):
            u = (x - box_x) / box_w if box_w else 0.0
            pixels[x, y] = gradient_colour((u + v) / 2.0)

    # Cut the shield out of the gradient.
    mask = Image.new("L", (work, work), 0)
    ImageDraw.Draw(mask).polygon(polygon, fill=255)

    canvas = Image.new("RGBA", (work, work), background)
    canvas.paste(gradient, (0, 0), mask)

    # Keyhole: circle and stem overlap, so they render as one white shape.
    draw = ImageDraw.Draw(canvas)
    cx, cy = KEYHOLE_CENTRE[0] * scale, KEYHOLE_CENTRE[1] * scale
    r = KEYHOLE_RADIUS * scale
    draw.ellipse([cx - r, cy - r, cx + r, cy + r], fill=KEYHOLE_COLOUR + (255,))
    draw.polygon([(x * scale, y * scale) for x, y in KEYHOLE_STEM], fill=KEYHOLE_COLOUR + (255,))

    return canvas.resize((size, size), Image.LANCZOS)


def parse_background(value):
    """"none" for transparency, otherwise a #rrggbb colour."""
    if value.lower() == "none":
        return (0, 0, 0, 0)
    text = value.lstrip("#")
    if len(text) != 6:
        raise argparse.ArgumentTypeError("background must be 'none' or a #rrggbb colour")
    return tuple(int(text[i:i + 2], 16) for i in (0, 2, 4)) + (255,)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--size", type=int, default=180, help="output size in pixels (default 180)")
    parser.add_argument(
        "--background",
        type=parse_background,
        default="#FFFFFF",
        help=(
            "background fill, or 'none' for transparency. Defaults to white: iOS "
            "discards alpha and composites home-screen icons onto black, which "
            "would lose the navy top of the shield."
        ),
    )
    parser.add_argument(
        "--out",
        default=str(PUBLIC_DIR / "apple-touch-icon.png"),
        help="output path (default frontend/public/apple-touch-icon.png)",
    )
    args = parser.parse_args()

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    icon = render(args.size, args.background)
    icon.save(out_path, "PNG")

    print("Icon written.")
    print(f"  File : {out_path}")
    print(f"  Size : {args.size}x{args.size}")
    print(f"  Source geometry: {PUBLIC_DIR / 'favicon.svg'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
