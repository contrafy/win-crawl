"""Render folded stacks ("root;child;leaf <count>" per line) as a static SVG flame graph.

Stdlib only. The output has no scripts, so it renders as an image on GitHub; each frame
carries a <title> tooltip with its sample count and share. Colours use the classic
flame graph "hot" palette, hashed from the frame name so a function keeps its colour
across graphs, on an explicit light background so the image reads the same in light and
dark themes.

    python tools/profile/flamegraph.py in.folded -o out.svg --title "..." [--subtitle "..."]
"""

import argparse
import hashlib
import html
import sys

FONT_SIZE = 12
FRAME_HEIGHT = 16
CHAR_WIDTH = 0.59 * FONT_SIZE  # Verdana average glyph width, close enough for clipping
PAD_X = 10
PAD_TOP = 3 * FONT_SIZE + 12  # title + subtitle
PAD_BOTTOM = FONT_SIZE + 10


class Node:
    __slots__ = ("name", "total", "children")

    def __init__(self, name):
        self.name = name
        self.total = 0
        self.children = {}


def read_folded(path):
    root = Node("all")
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            stack, _, count = line.rpartition(" ")
            n = int(count)
            root.total += n
            node = root
            for frame in stack.split(";"):
                child = node.children.get(frame)
                if child is None:
                    child = node.children[frame] = Node(frame)
                child.total += n
                node = child
    return root


def colour(name):
    # Classic "hot" palette: red..yellow, deterministic per function name.
    h = hashlib.md5(name.encode("utf-8")).digest()
    v1, v2, v3 = h[0] / 255, h[1] / 255, h[2] / 255
    return f"rgb({205 + int(50 * v3)},{int(230 * v1)},{int(55 * v2)})"


def depth_of(node, scale, min_px):
    best = 0
    for c in node.children.values():
        if c.total * scale >= min_px:
            best = max(best, 1 + depth_of(c, scale, min_px))
    return best


def render(root, title, subtitle, width, min_px, unit):
    scale = (width - 2 * PAD_X) / root.total if root.total else 0
    depth = depth_of(root, scale, min_px) + 1
    height = PAD_TOP + depth * FRAME_HEIGHT + PAD_BOTTOM
    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" font-family="Verdana, sans-serif" font-size="{FONT_SIZE}">',
        '<defs><linearGradient id="bg" y1="0" y2="1" x1="0" x2="0">'
        '<stop stop-color="#eeeeee" offset="5%"/><stop stop-color="#eeeeb0" offset="95%"/>'
        "</linearGradient></defs>",
        f'<rect x="0" y="0" width="{width}" height="{height}" fill="url(#bg)"/>',
        f'<text x="{width / 2:.0f}" y="{FONT_SIZE + 8}" text-anchor="middle" font-size="{FONT_SIZE + 5}" '
        f'fill="#000">{html.escape(title)}</text>',
    ]
    if subtitle:
        out.append(
            f'<text x="{width / 2:.0f}" y="{2 * FONT_SIZE + 14}" text-anchor="middle" fill="#555">'
            f"{html.escape(subtitle)}</text>"
        )
    out.append(
        f'<text x="{PAD_X}" y="{height - 6}" fill="#555">Frame width = share of {root.total:,} {unit}; '
        "hover a frame for its count. Narrow frames are omitted.</text>"
    )
    base_y = height - PAD_BOTTOM - FRAME_HEIGHT

    def emit(node, x, level):
        w = node.total * scale
        if w < min_px:
            return
        y = base_y - level * FRAME_HEIGHT
        pct = 100.0 * node.total / root.total
        label = node.name
        tip = html.escape(f"{label} ({node.total:,} {unit}, {pct:.2f}%)")
        fill = "rgb(240,240,240)" if level == 0 else colour(label)
        out.append(
            f'<g><title>{tip}</title><rect x="{x:.1f}" y="{y}" width="{max(w - 0.5, 0.1):.1f}" '
            f'height="{FRAME_HEIGHT - 1}" rx="2" fill="{fill}"/>'
        )
        chars = int((w - 6) / CHAR_WIDTH)
        if chars >= 3:
            # Narrow frames drop the "module!" prefix first, then truncate.
            text = label if len(label) <= chars else label.split("!", 1)[-1]
            if len(text) > chars:
                text = text[: chars - 2] + ".."
            out.append(f'<text x="{x + 3:.1f}" y="{y + FRAME_HEIGHT - 4}">{html.escape(text)}</text>')
        out.append("</g>")
        cx = x
        # Alphabetical order, as in the classic tool: position carries no time meaning.
        for name in sorted(node.children):
            child = node.children[name]
            emit(child, cx, level + 1)
            cx += child.total * scale

    emit(root, PAD_X, 0)
    out.append("</svg>")
    return "\n".join(out) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("folded")
    ap.add_argument("-o", "--out", required=True)
    ap.add_argument("--title", default="Flame graph")
    ap.add_argument("--subtitle", default="")
    ap.add_argument("--width", type=int, default=1200)
    ap.add_argument("--min-px", type=float, default=0.5, help="omit frames narrower than this (default 0.5)")
    ap.add_argument("--unit", default="samples")
    args = ap.parse_args()
    root = read_folded(args.folded)
    if root.total == 0:
        sys.exit(f"{args.folded}: no samples")
    svg = render(root, args.title, args.subtitle, args.width, args.min_px, args.unit)
    with open(args.out, "w", encoding="utf-8", newline="\n") as f:
        f.write(svg)
    print(f"{args.out}: {root.total:,} {args.unit}, {len(svg):,} bytes")


if __name__ == "__main__":
    main()
