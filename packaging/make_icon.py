"""Draws packaging/plainsight.ico (same design as plainsight/web/favicon.svg). Needs Pillow."""
from pathlib import Path

from PIL import Image, ImageDraw

S = 1024  # draw large, downsample for smooth edges
BG, RED = (22, 27, 34, 255), (248, 81, 73, 255)


def draw() -> Image.Image:
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    u = S / 64
    d.rounded_rectangle([0, 0, S - 1, S - 1], radius=14 * u, fill=BG)
    # eye outline: two arcs meeting at the corners
    top = [(8 * u, 32 * u)] + [(x * u, (32 - 17 * (1 - ((x - 32) / 24) ** 2)) * u) for x in range(9, 56)] + [(56 * u, 32 * u)]
    bottom = [(x * u, (32 + 17 * (1 - ((x - 32) / 24) ** 2)) * u) for x in range(55, 8, -1)]
    d.line(top + bottom + [top[0]], fill=RED, width=int(4 * u), joint="curve")
    d.ellipse([23 * u, 23 * u, 41 * u, 41 * u], fill=RED)
    d.rounded_rectangle([28 * u, 28 * u, 36 * u, 36 * u], radius=1.5 * u, fill=BG)
    return img


if __name__ == "__main__":
    out = Path(__file__).with_name("plainsight.ico")
    draw().resize((256, 256), Image.LANCZOS).save(out, sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    print(f"wrote {out}")
