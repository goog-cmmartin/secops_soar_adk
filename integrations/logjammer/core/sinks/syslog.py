"""Syslog network sink for Log Jammer OSS."""

import socket
import ssl
from typing import Optional
from .base import BaseSink
from ..models import GeneratedScenario, LogEntry


class SyslogSink(BaseSink):
  """Emits log events over UDP, TCP, or TLS to a remote Syslog daemon."""

  def __init__(
      self,
      host: str = "localhost",
      port: int = 514,
      protocol: str = "udp",  # 'udp', 'tcp', 'tls'
      facility: int = 1,  # user-level messages
      severity: int = 6,  # informational
  ):
    self.host = host
    self.port = port
    self.protocol = protocol.lower()
    self.facility = facility
    self.severity = severity

  def _format_syslog_message(self, entry: LogEntry) -> bytes:
    # If the content already has a syslog header, emit as-is, else prepend priority tag
    content = entry.content.strip()
    if not content.startswith("<"):
      pri = (self.facility * 8) + self.severity
      content = f"<{pri}>{content}"
    return (content + "\n").encode("utf-8")

  def emit(self, scenario: GeneratedScenario) -> int:
    logs = scenario.get_flattened_logs()
    count = 0

    if self.protocol == "udp":
      sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      try:
        for entry in logs:
          msg = self._format_syslog_message(entry)
          sock.sendto(msg, (self.host, self.port))
          count += 1
      finally:
        sock.close()
    elif self.protocol in ("tcp", "tls"):
      raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      if self.protocol == "tls":
        context = ssl.create_default_context()
        sock = context.wrap_socket(raw_sock, server_hostname=self.host)
      else:
        sock = raw_sock

      try:
        sock.connect((self.host, self.port))
        for entry in logs:
          msg = self._format_syslog_message(entry)
          sock.sendall(msg)
          count += 1
      finally:
        sock.close()

    return count

  def emit_entry(self, entry: LogEntry) -> bool:
    msg = self._format_syslog_message(entry)
    if self.protocol == "udp":
      sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      try:
        sock.sendto(msg, (self.host, self.port))
        return True
      finally:
        sock.close()
    return False
