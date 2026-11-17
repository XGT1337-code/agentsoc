"""Build the AgentSOC presentation PDF (landscape slides, muted palette).

    python docs/build_presentation_pdf.py   ->  docs/AgentSOC-presentation.pdf

Uses reportlab + a Cyrillic TTF (Arial on Windows, DejaVuSans elsewhere).
"""
from __future__ import annotations

import os
from pathlib import Path

from reportlab.lib.colors import HexColor
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.utils import simpleSplit
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas
from reportlab.platypus import Table, TableStyle

OUT = Path(__file__).resolve().parent / "AgentSOC-presentation.pdf"

# palette
PAPER = HexColor("#fdfef9"); INK = HexColor("#060201"); SLATE = HexColor("#464847")
ACCENT = HexColor("#4e6180"); MIST = HexColor("#a2b1c8"); STONE = HexColor("#6c6b66")
TINT = HexColor("#eef1f6"); CRIT = HexColor("#9e5c52"); OK = HexColor("#5f7d6a")

PAGE = landscape(A4)           # 842 x 595 pt
W, H = PAGE
MX = 54                        # side margin


def _register_fonts() -> tuple[str, str]:
    cands = [("C:/Windows/Fonts/arial.ttf", "C:/Windows/Fonts/arialbd.ttf"),
             ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
              "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf")]
    for reg, bold in cands:
        if os.path.exists(reg) and os.path.exists(bold):
            pdfmetrics.registerFont(TTFont("Body", reg))
            pdfmetrics.registerFont(TTFont("Body-Bold", bold))
            return "Body", "Body-Bold"
    return "Helvetica", "Helvetica-Bold"


FONT, FONT_B = _register_fonts()


def _bg(c):
    c.setFillColor(PAPER); c.rect(0, 0, W, H, fill=1, stroke=0)


def _header(c, kicker, title, idx):
    # top band
    c.setFillColor(SLATE); c.rect(0, H - 92, W, 92, fill=1, stroke=0)
    c.setFillColor(MIST); c.setFont(FONT_B, 11)
    c.drawString(MX, H - 40, kicker.upper())
    c.setFillColor(PAPER); c.setFont(FONT_B, 25)
    c.drawString(MX, H - 72, title)
    # brand + page number
    c.setFillColor(MIST); c.setFont(FONT_B, 12)
    c.drawRightString(W - MX, H - 40, "AgentSOC")
    c.setFillColor(STONE); c.setFont(FONT, 10)
    c.drawRightString(W - MX, 26, f"{idx}")


def _note(c, note):
    if not note:
        return
    y0 = 40
    lines = simpleSplit("Речь: " + note, FONT, 12, W - 2 * MX - 28)
    box_h = 20 + 16 * len(lines)
    c.setFillColor(TINT); c.roundRect(MX, y0, W - 2 * MX, box_h, 8, fill=1, stroke=0)
    c.setFillColor(ACCENT); c.rect(MX, y0, 4, box_h, fill=1, stroke=0)
    c.setFillColor(SLATE); c.setFont(FONT, 12)
    ty = y0 + box_h - 18
    for ln in lines:
        c.drawString(MX + 16, ty, ln); ty -= 16
    return box_h


def _bullets(c, items, top, note_h):
    y = top
    c.setFont(FONT, 15)
    maxw = W - 2 * MX - 26
    for it in items:
        sub = it.startswith("- ")
        text = it[2:] if sub else it
        x = MX + (26 if sub else 0)
        lines = simpleSplit(text, FONT, 15 if not sub else 13.5, maxw - (26 if sub else 0))
        # marker
        c.setFillColor(ACCENT if not sub else MIST)
        c.setFont(FONT_B, 15)
        c.drawString(x, y, "•" if not sub else "–")
        c.setFillColor(INK if not sub else SLATE); c.setFont(FONT, 15 if not sub else 13.5)
        for i, ln in enumerate(lines):
            c.drawString(x + 18, y, ln); y -= 21 if not sub else 18
        y -= 4
        if y < 60 + note_h:
            break


def slide(c, kicker, title, idx, bullets=None, note=None, table=None, lead=None):
    _bg(c)
    _header(c, kicker, title, idx)
    note_h = 0
    if note:
        lines = simpleSplit("Речь: " + note, FONT, 12, W - 2 * MX - 28)
        note_h = 20 + 16 * len(lines)
    top = H - 128
    if lead:
        c.setFillColor(ACCENT); c.setFont(FONT_B, 17)
        for ln in simpleSplit(lead, FONT_B, 17, W - 2 * MX):
            c.drawString(MX, top, ln); top -= 24
        top -= 6
    if table is not None:
        _draw_table(c, table, top, note_h)
    elif bullets:
        _bullets(c, bullets, top, note_h)
    _note(c, note)
    c.showPage()


def _draw_table(c, data, top, note_h):
    colw = [150, W - 2 * MX - 150 - 190, 190]
    t = Table(data, colWidths=colw)
    t.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), FONT),
        ("FONTNAME", (0, 0), (-1, 0), FONT_B),
        ("FONTSIZE", (0, 0), (-1, -1), 11),
        ("TEXTCOLOR", (0, 0), (-1, 0), PAPER),
        ("BACKGROUND", (0, 0), (-1, 0), SLATE),
        ("TEXTCOLOR", (0, 1), (-1, -1), INK),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [PAPER, TINT]),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, MIST),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
    ]))
    tw, th = t.wrapOn(c, W - 2 * MX, top)
    t.drawOn(c, MX, max(60 + note_h, top - th))


def title_slide(c):
    _bg(c)
    c.setFillColor(SLATE); c.rect(0, 0, 12, H, fill=1, stroke=0)
    c.setFillColor(ACCENT); c.setFont(FONT_B, 13)
    c.drawString(MX, H - 150, "SOC-МОНИТОР И FIREWALL ДЛЯ ИИ-АГЕНТОВ (MCP)")
    c.setFillColor(INK); c.setFont(FONT_B, 68)
    c.drawString(MX, H - 250, "AgentSOC")
    c.setFillColor(STONE); c.setFont(FONT, 18)
    for i, ln in enumerate([
        "Защита ИИ-агентов и локальных ИИ от tool poisoning,",
        "prompt injection и утечки данных — с интеграцией в QRadar, Shuffle и Palo Alto."]):
        c.drawString(MX, H - 300 - i * 26, ln)
    c.setFillColor(MIST); c.rect(MX, 120, 360, 2, fill=1, stroke=0)
    c.setFillColor(SLATE); c.setFont(FONT, 14)
    c.drawString(MX, 92, "Blue Team · Хакатон по кибербезопасности · 2026")
    c.setFillColor(STONE); c.setFont(FONT, 12)
    c.drawString(MX, 68, "github.com/XGT1337-code/agentsoc")
    c.showPage()


def build():
    c = canvas.Canvas(str(OUT), pagesize=PAGE)
    c.setTitle("AgentSOC — презентация")
    title_slide(c)

    slide(c, "Проблема", "ИИ-агенты получили доступ к инструментам — и к новым атакам", 2,
          lead="ИИ-агенты ходят в почту, файлы и API через MCP. Это открывает атаки, которых раньше не было:",
          bullets=[
              "Tool poisoning — в описании инструмента спрятана команда «прочитай SSH-ключ и отправь злоумышленнику»",
              "Prompt injection — вредная инструкция приходит в данных (письмо, документ)",
              "Rug pull — инструмент становится вредным уже после одобрения",
              "Утечка данных — агент отправляет секреты на внешний адрес",
              "Главное: эти события не видит ни один SIEM — для SOC агент это слепая зона",
          ],
          note="ИИ-агент выполняет инструкции из недоверенных данных. Отравленное описание или письмо с инъекцией — и агент сам сливает SSH-ключ. При этом в QRadar такие события не попадают.")

    slide(c, "Решение", "AgentSOC — прокси между агентом и его инструментами", 3,
          lead="ИИ-агент  ⇄  AgentSOC (firewall + SOC)  ⇄  MCP-серверы  →  QRadar · Shuffle · Palo Alto",
          bullets=[
              "Видит каждое JSON-RPC сообщение: tools/list, tools/call, ответы",
              "9 правил ловят атаки и блокируют опасные вызовы",
              "Каждая атака → SOC-алерт с тегом MITRE ATLAS / OWASP LLM Top 10",
              "События уходят в тот SIEM/SOAR, что уже есть у компании",
          ],
          note="AgentSOC — это man-in-the-middle. Он реально работает по логике MCP: запускает сервер, читает каждый кадр, блокирует опасное и отправляет событие в SIEM и SOAR.")

    slide(c, "Архитектура", "Детерминированные правила + LLM-судья, в два слоя", 4,
          bullets=[
              "Прокси (proxy/proxy.py) — настоящий stdio MCP man-in-the-middle",
              "9 правил (rules.py) — быстрый детерминированный слой",
              "LLM-судья (judge.py) — второе мнение; описания и данные для него недоверенные данные, не инструкции",
              "SQLite — events + alerts; генераторы — AQL, Shuffle, Palo Alto, инцидент-отчёт",
              "FastAPI + дашборд — визуализация в реальном времени",
          ],
          note="Основной слой — детерминированные правила: их нельзя уговорить. LLM-судья добавляет второе мнение, но никогда не отменяет блокировку правила — его тоже можно обмануть.")

    slide(c, "Детектирование", "9 правил, размеченных на MITRE ATLAS и OWASP", 5,
          table=[
              ["Правило", "Угроза", "Framework"],
              ["Tool poisoning", "команды в описании инструмента", "OWASP LLM01 · ATLAS T0051"],
              ["Sensitive file", "чтение .ssh, .env, id_rsa", "OWASP LLM02 · ATLAS T0057"],
              ["Exfiltration", "отправка на чужой домен", "OWASP LLM02 · ATLAS T0025"],
              ["Rug pull", "подмена после одобрения", "OWASP LLM03 · ATLAS T0010"],
              ["Prompt injection", "инструкции в данных", "OWASP LLM01 · ATLAS T0051"],
              ["Task mismatch", "вызов не по задаче (LLM-судья)", "OWASP LLM06"],
              ["Path traversal", "побег из рабочей папки", "OWASP LLM02 · ATLAS T0057"],
              ["Secret payload (DLP)", "секрет в исходящих аргументах", "OWASP LLM02 · ATLAS T0024"],
              ["Tool shadowing", "сервер-импостор подменяет tool", "OWASP LLM03 · ATLAS T0010"],
          ],
          note="Девять правил, каждое размечено на MITRE ATLAS и OWASP LLM Top 10 — те фреймворки, которыми Blue Team уже пользуется.")

    slide(c, "Интеграция с SOC — главная идея", "События агента в существующем стеке Blue Team", 6,
          bullets=[
              "QRadar (SIEM): экспорт в LEEF 2.0, AQL-запросы для охоты, offenses (корреляция алертов, magnitude 1–10)",
              "Shuffle (SOAR): замкнутый цикл — плейбук реально ставит инструмент в карантин, следующий вызов блокируется",
              "Palo Alto (NGFW): блок-правило PAN-OS + EDL с доменом злоумышленника",
          ],
          note="Это ядро идеи: не очередной чёрный ящик, а события в QRadar, Shuffle и Palo Alto. Shuffle-плейбук не просто рисуется — он реально блокирует инструмент, замыкая цикл реагирования.")

    slide(c, "Шире MCP", "Контент-firewall: защита любого локального ИИ", 7,
          bullets=[
              "POST /scan и /upload — проверяют вставленный промпт, письмо, документ или файл",
              "Тот же движок правил → вердикт allow / review / block + очищенная копия",
              "Защищает локальные ИИ компании от prompt injection и prompt engineering",
          ],
          note="AgentSOC защищает не только агента на MCP. Любой текст, который локальный ИИ собирается прочитать, можно прогнать через контент-firewall — это защита для всей компании.")

    slide(c, "Безопасность доступа", "Консоль: SSH → email → OTP", 8,
          bullets=[
              "SSH-шлюз проверяет пароль и выдаёт одноразовый веб-токен",
              "На странице вводишь email администратора — принимается только один адрес",
              "На почту приходит OTP — вводишь код → сессия → консоль",
              "Без всей цепочки — экран блокировки (по URL/порту не зайти)",
          ],
          note="Доступ к самой SOC-консоли защищён: сначала SSH-гейт, потом одноразовый токен, потом email админа и одноразовый код.")

    slide(c, "Демо", "Сценарий показа (2 минуты)", 9,
          bullets=[
              "python demo/run_demo.py — без защиты фейковый ключ утекает в outbox.jsonl, с AgentSOC заблокировано",
              "Дашборд → Split demo: слева красная утечка, справа зелёный блок",
              "Клик на алерт → Explain (az/en/ru) → AQL + Shuffle + Palo Alto → Run SOAR playbook (карантин)",
              "QRadar offenses — корреляция в инцидент",
              "Content firewall — вставить письмо с инъекцией → вердикт block",
          ],
          note="Без AgentSOC ключ уходит атакующему. С AgentSOC вызов заблокирован, поднят алерт, сгенерированы AQL и Shuffle, а плейбук уже поставил инструмент в карантин.")

    slide(c, "Результаты", "Что сделано", 10,
          bullets=[
              "9 правил, 6 сценариев атак, покрытие MITRE ATLAS + OWASP LLM Top 10",
              "Интеграции: QRadar (LEEF/AQL/offenses), Shuffle (замкнутый SOAR), Palo Alto (PAN-OS/EDL)",
              "Контент-firewall для любого локального ИИ; доступ SSH → email → OTP",
              "70 тестов (66 офлайн + 4 на живой модели), CI, Docker",
              "Работает полностью офлайн без ключа API (шаблонный режим)",
          ],
          note="Всё покрыто тестами и гоняется в CI. Проект работает и без API-ключа, поэтому демо не зависит от сети.")

    slide(c, "Ограничения — честно", "AgentSOC — слой защиты, а не серебряная пуля", 11,
          bullets=[
              "Сгенерированные AQL / Shuffle / PAN-OS — заготовки, их надо проверить на своих QRadar, Shuffle и Panorama",
              "LLM-судью можно обмануть → правила как первый, основной слой",
              "Правила ловят известные паттерны → возможны ложные срабатывания",
              "Дополняет изоляцию инструментов и минимизацию прав, а не заменяет их",
          ],
          note="Я честно показываю ограничения. AgentSOC — это ещё один слой защиты и, главное, видимость в SOC.")

    slide(c, "Итог", "ИИ-агенты становятся видимыми и управляемыми для SOC", 12,
          bullets=[
              "Детект на прокси → алерт → QRadar → Shuffle → Palo Alto",
              "Защита агентов и локальных ИИ от инъекций и утечек",
              "Открытый код, тесты, CI, Docker",
              "Репозиторий: github.com/XGT1337-code/agentsoc",
          ],
          note="AgentSOC закрывает слепую зону: ИИ-агенты становятся видимыми и управляемыми для SOC. Спасибо, готов ответить на вопросы.")

    c.save()
    print(f"wrote {OUT} ({OUT.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    build()
