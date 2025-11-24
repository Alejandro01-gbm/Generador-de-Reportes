import logging
import threading
from datetime import datetime

class UILogHandler(logging.Handler):
    """Envía logs a la UI de forma segura."""
    def __init__(self, append_log_safe):
        super().__init__()
        self.append_log_safe = append_log_safe

    def emit(self, record):
        msg = self.format(record)
        self.append_log_safe(msg)

def call_on_main(root, func, *args, **kwargs):
    """Ejecuta func en el hilo principal (si es necesario)."""
    if threading.current_thread() is threading.main_thread():
        func(*args, **kwargs)
    else:
        root.after(0, lambda: func(*args, **kwargs))

def ts_line(text: str) -> str:
    return f"[{datetime.now().strftime('%H:%M:%S')}] {text}"
