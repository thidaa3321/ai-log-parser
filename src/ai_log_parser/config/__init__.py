# src/ai_log_parser/__init__.py

"""
ai_log_parser — AI-powered dynamic log parser for SOC pipelines.

Public API
----------
::

    from ai_log_parser import AIParseEngine
    from ai_log_parser.engine.preprocessor import LogPreprocessor
    from ai_log_parser.config.loader import ConfigLoader
    from ai_log_parser.engine.queue import InProcessQueue

    config = ConfigLoader.load_default()
    queue  = InProcessQueue(config.queue_max_size)

    preprocessor = LogPreprocessor()
    engine       = AIParseEngine()

    hint  = preprocessor.detect(raw_line)
    event = await engine.parse(raw_line, hint)
"""

from ai_log_parser.engine.parser import AIParseEngine
from ai_log_parser.engine.preprocessor import LogPreprocessor
from ai_log_parser.config.loader import ConfigLoader
from ai_log_parser.engine.queue import InProcessQueue

__version__ = "1.0.0"
__author__  = "SOC Engineering"

__all__ = [
    "AIParseEngine",
    "LogPreprocessor",
    "ConfigLoader",
    "InProcessQueue",
]
