"""Plain-language explanation of an alert in az / en / ru.

With an API key the LLM writes the explanation. Without one, deterministic
templates per rule and language are used, so the dashboard always has text.
"""
from __future__ import annotations

from common import llm

LANGS = ("az", "en", "ru")

# Short per-rule explanation templates. {server}/{tool} are filled in.
_TEMPLATES = {
    "en": {
        "R1_TOOL_POISONING": "The tool '{tool}' on server '{server}' hides instructions in its description that try to make the AI leak secrets. AgentSOC removed/flagged the tool before the agent could trust it.",
        "R2_SENSITIVE_FILE": "Something tried to read a secret file (like an SSH key or .env) through '{tool}'. AgentSOC blocked the read.",
        "R3_EXFILTRATION": "'{tool}' tried to send data to an outside email address that is not on the allow list. AgentSOC blocked the send to stop data exfiltration.",
        "R4_RUG_PULL": "The tool '{tool}' changed its definition after it was approved (a 'rug pull'). AgentSOC detected the change and blocked it.",
        "R5_DATA_INJECTION": "Data returned by '{tool}' contained hidden instructions aimed at the AI (prompt injection). AgentSOC redacted or blocked that content.",
        "R6_TASK_MISMATCH": "The call to '{tool}' did not match what the user actually asked for. AgentSOC flagged it as suspicious.",
        "R0_SOAR_BLOCKLIST": "The tool '{tool}' is on the SOAR blocklist, so AgentSOC blocked the call.",
    },
    "ru": {
        "R1_TOOL_POISONING": "Инструмент '{tool}' на сервере '{server}' прячет в своём описании команды, которые пытаются заставить ИИ слить секреты. AgentSOC удалил/пометил инструмент до того, как агент ему доверился.",
        "R2_SENSITIVE_FILE": "Кто-то попытался прочитать секретный файл (ключ SSH или .env) через '{tool}'. AgentSOC заблокировал чтение.",
        "R3_EXFILTRATION": "'{tool}' попытался отправить данные на внешний адрес, которого нет в белом списке. AgentSOC заблокировал отправку, чтобы не допустить утечку.",
        "R4_RUG_PULL": "Инструмент '{tool}' изменил своё описание после одобрения (подмена, 'rug pull'). AgentSOC обнаружил изменение и заблокировал его.",
        "R5_DATA_INJECTION": "В данных от '{tool}' оказались скрытые инструкции для ИИ (prompt injection). AgentSOC вырезал или заблокировал этот текст.",
        "R6_TASK_MISMATCH": "Вызов '{tool}' не соответствует тому, что просил пользователь. AgentSOC пометил его как подозрительный.",
        "R0_SOAR_BLOCKLIST": "Инструмент '{tool}' находится в блок-листе SOAR, поэтому AgentSOC заблокировал вызов.",
    },
    "az": {
        "R1_TOOL_POISONING": "'{server}' serverindəki '{tool}' aləti təsvirində süni intellekti sirləri sızdırmağa məcbur edən gizli təlimatlar saxlayır. AgentSOC agent ona etibar etməzdən əvvəl aləti sildi/işarələdi.",
        "R2_SENSITIVE_FILE": "Kimsə '{tool}' vasitəsilə gizli faylı (SSH açarı və ya .env) oxumağa cəhd etdi. AgentSOC oxunuşu blokladı.",
        "R3_EXFILTRATION": "'{tool}' məlumatı ağ siyahıda olmayan xarici e-poçt ünvanına göndərməyə cəhd etdi. AgentSOC məlumat sızmasının qarşısını almaq üçün göndərməni blokladı.",
        "R4_RUG_PULL": "'{tool}' aləti təsdiqləndikdən sonra təyinatını dəyişdi ('rug pull'). AgentSOC dəyişikliyi aşkar edib blokladı.",
        "R5_DATA_INJECTION": "'{tool}' qaytardığı məlumatda süni intellektə yönəlmiş gizli təlimatlar var idi (prompt injection). AgentSOC həmin məzmunu redaktə etdi və ya blokladı.",
        "R6_TASK_MISMATCH": "'{tool}' çağırışı istifadəçinin istədiyi ilə uyğun gəlmirdi. AgentSOC onu şübhəli kimi işarələdi.",
        "R0_SOAR_BLOCKLIST": "'{tool}' aləti SOAR blok-siyahısındadır, buna görə AgentSOC çağırışı blokladı.",
    },
}

_SYSTEM = {
    "en": "You are a SOC analyst. Explain this AI-agent security alert to a junior analyst in 2-3 plain English sentences. Say what happened and why it matters. No markdown.",
    "ru": "Ты аналитик SOC. Объясни это предупреждение безопасности ИИ-агента младшему аналитику в 2-3 простых предложениях на русском. Скажи, что произошло и почему это важно. Без markdown.",
    "az": "Sən SOC analitiksən. Bu süni intellekt agenti üçün təhlükəsizlik xəbərdarlığını kiçik analitikə 2-3 sadə Azərbaycan dilində cümlə ilə izah et. Nə baş verdiyini və niyə önəmli olduğunu de. Markdown yoxdur.",
}


def explain(alert: dict, lang: str = "en") -> dict:
    lang = lang if lang in LANGS else "en"
    tmpl = _TEMPLATES[lang].get(
        alert.get("rule_id", ""),
        _TEMPLATES[lang]["R6_TASK_MISMATCH"],
    ).format(server=alert.get("server", "?"), tool=alert.get("tool") or "?")

    text = tmpl
    source = "template"
    if llm.has_key():
        user = (
            f"Alert: {alert.get('title')}\nRule: {alert.get('rule_id')}\n"
            f"Server: {alert.get('server')} Tool: {alert.get('tool')}\n"
            f"Reason: {alert.get('reason')}\nFramework tag: {alert.get('tag')}\n"
            f"Action taken: {alert.get('action')}"
        )
        llm_text = llm.ask_text(_SYSTEM[lang], user, max_tokens=400)
        if llm_text:
            text, source = llm_text, "llm"
    return {"lang": lang, "text": text, "source": source}
