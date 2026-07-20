"""Render the MIT-licensed Tabler arrows-join derivative as PNG and ICO."""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw


ROOT = Path(__file__).resolve().parents[1]
ICON_DIR = ROOT / "assets" / "icon"
PNG_PATH = ICON_DIR / "app-icon.png"
ICO_PATH = ICON_DIR / "app-icon.ico"
BASE_SIZE = 256
ICO_SIZES = (16, 20, 24, 32, 40, 48, 64, 128, 256)


def scaled(points: list[tuple[float, float]], scale: float) -> list[tuple[int, int]]:
    return [(round(x * scale), round(y * scale)) for x, y in points]


def render(size: int) -> Image.Image:
    supersample = 4
    canvas_size = size * supersample
    scale = canvas_size / 24.0
    image = Image.new("RGBA", (canvas_size, canvas_size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)

    draw.rounded_rectangle(
        (0.75 * scale, 0.75 * scale, 23.25 * scale, 23.25 * scale),
        radius=5.25 * scale,
        fill="#08090b",
    )
    draw.rounded_rectangle(
        (1.25 * scale, 1.25 * scale, 22.75 * scale, 22.75 * scale),
        radius=4.75 * scale,
        outline="#30343a",
        width=max(1, round(scale)),
    )

    arrow_width = max(1, round(2.25 * scale))
    color = "#f7f7f7"
    paths = (
        [(3, 7), (8, 7), (11.5, 12), (21, 12)],
        [(3, 17), (8, 17), (11.495, 12)],
        [(18, 15), (21, 12), (18, 9)],
    )
    for path in paths:
        draw.line(scaled(path, scale), fill=color, width=arrow_width, joint="curve")

    return image.resize((size, size), Image.Resampling.LANCZOS)


def main() -> None:
    ICON_DIR.mkdir(parents=True, exist_ok=True)
    base = render(BASE_SIZE)
    base.save(PNG_PATH, format="PNG", optimize=True)
    base.save(ICO_PATH, format="ICO", sizes=[(size, size) for size in ICO_SIZES])


if __name__ == "__main__":
    main()
