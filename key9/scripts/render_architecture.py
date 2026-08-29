#!/usr/bin/env python3
"""Render the exact KEY-9 architecture diagram used for Devpost."""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "docs" / "assets" / "watch-dawg-key9-architecture.png"
FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(BOLD if bold else FONT, size)


def rounded(draw: ImageDraw.ImageDraw, box: tuple[int, int, int, int], *, fill: str, outline: str, width: int = 3, radius: int = 24) -> None:
    draw.rounded_rectangle(box, radius=radius, fill=fill, outline=outline, width=width)


def node(
    draw: ImageDraw.ImageDraw,
    box: tuple[int, int, int, int],
    kicker: str,
    title: str,
    lines: list[str],
    *,
    outline: str = "#315772",
    fill: str = "#122b43",
) -> None:
    rounded(draw, box, fill=fill, outline=outline)
    x1, y1, _, _ = box
    draw.text((x1 + 35, y1 + 33), kicker, font=font(18, True), fill="#8fa9bd")
    draw.text((x1 + 35, y1 + 82), title, font=font(23, True), fill="#f8fbff")
    for index, line in enumerate(lines):
        draw.text((x1 + 35, y1 + 127 + index * 30), line, font=font(20), fill="#c5d6e5")


def arrow(draw: ImageDraw.ImageDraw, points: list[tuple[int, int]], *, color: str = "#72d4ff", width: int = 6) -> None:
    draw.line(points, fill=color, width=width, joint="curve")
    x2, y2 = points[-1]
    x1, y1 = points[-2]
    if abs(x2 - x1) >= abs(y2 - y1):
        direction = 1 if x2 > x1 else -1
        tip = [(x2, y2), (x2 - 18 * direction, y2 - 11), (x2 - 18 * direction, y2 + 11)]
    else:
        direction = 1 if y2 > y1 else -1
        tip = [(x2, y2), (x2 - 11, y2 - 18 * direction), (x2 + 11, y2 - 18 * direction)]
    draw.polygon(tip, fill=color)


def main() -> None:
    image = Image.new("RGB", (1800, 1200), "#07111f")
    draw = ImageDraw.Draw(image)

    for y in range(1200):
        ratio = y / 1199
        draw.line((0, y, 1800, y), fill=(7 + int(9 * ratio), 17 + int(19 * ratio), 31 + int(27 * ratio)))

    draw.ellipse((1400, -210, 1930, 320), fill="#102f47")
    draw.ellipse((-250, 880, 430, 1560), fill="#1c252d")

    draw.text((90, 60), "WATCH-DAWG KEY-9", font=font(57, True), fill="#f8fbff")
    draw.text((90, 125), "Give the goal. Never give the secret.", font=font(27), fill="#adc4d8")
    rounded(draw, (1390, 60, 1710, 112), fill="#f08a35", outline="#f08a35", radius=26)
    draw.text((1550, 86), "TASKMASTER • CONTEST SANDBOX", anchor="mm", font=font(16, True), fill="#07111f")

    node(draw, (90, 205, 480, 385), "1 • HUMAN CONTROL", "Contractor + KEY-9 Console", ["Operational goal in. Redacted proof out.", "Final sandbox export requires a click."])
    node(draw, (705, 205, 1095, 385), "2 • REASONING LAYER", "Gemini 3.5 Flash + ADK", ["Plans the mission and selects tools.", "Sees aliases and outcomes—never secrets."], outline="#72d4ff", fill="#15324c")
    node(draw, (1320, 205, 1710, 385), "3 • DETERMINISTIC GUARD", "Fail-Closed Policy Engine", ["Exact host • scope • TTL • approval", "Unknown or unsafe request = no action."], outline="#f4a340", fill="#3a251c")

    arrow(draw, [(480, 295), (690, 295)])
    arrow(draw, [(1095, 295), (1305, 295)])
    draw.text((585, 265), "GOAL", anchor="mm", font=font(17, True), fill="#8fa9bd")
    draw.text((1200, 263), "ALIAS + TARGET + SCOPE", anchor="mm", font=font(16, True), fill="#8fa9bd")

    draw.rounded_rectangle((575, 485, 1225, 815), radius=32, outline="#f4a340", width=3)
    for x in range(595, 1205, 24):
        draw.line((x, 485, min(x + 12, 1205), 485), fill="#f4a340", width=4)
        draw.line((x, 815, min(x + 12, 1205), 815), fill="#f4a340", width=4)
    draw.text((605, 505), "SECRET TRUST BOUNDARY • OUTSIDE MODEL CONTEXT", font=font(17, True), fill="#f4a340")
    node(draw, (625, 555, 1175, 735), "4 • SERVER-ONLY EXECUTION", "Private Approval Bridge + Broker", ["Creates a one-use lease and injects the", "credential only at the connector boundary."], outline="#f4a340", fill="#3a251c")

    arrow(draw, [(1515, 385), (1515, 440), (1210, 470), (1105, 545)])
    arrow(draw, [(285, 385), (285, 455), (525, 500), (625, 600)], color="#f4a340")
    draw.text((350, 455), "HUMAN APPROVAL", font=font(17, True), fill="#f4a340")

    node(draw, (90, 915, 440, 1075), "GOOGLE CLOUD", "Cloud Run", ["ADK agent runtime"], fill="#102a3e")
    node(draw, (515, 915, 865, 1075), "CREDENTIAL STORE", "Secret Manager", ["Versioned alias mapping"], fill="#102a3e")
    node(draw, (940, 915, 1290, 1075), "SCOPED CONNECTORS", "Watch-Dawg + Drive", ["Seeded job and receipts"], fill="#102a3e")
    node(draw, (1365, 915, 1710, 1075), "REVERSIBLE OUTPUT", "Accounting Sandbox", ["Export draft + audit proof"], fill="#102a3e")

    arrow(draw, [(730, 815), (620, 855), (285, 900)])
    arrow(draw, [(820, 815), (780, 855), (690, 900)])
    arrow(draw, [(980, 815), (1040, 855), (1115, 900)])
    arrow(draw, [(1085, 815), (1250, 855), (1538, 900)])

    draw.text((90, 1135), "Security invariant: the model can request an approved action, but it cannot retrieve a secret or approve its own write.", font=font(24), fill="#adc4d8")

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    image.save(OUTPUT, optimize=True)
    print(OUTPUT)


if __name__ == "__main__":
    main()
