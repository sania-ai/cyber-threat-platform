
import ipaddress
import re
from datetime import datetime
from typing import Literal, Optional
from urllib.parse import urlparse

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)


class ThreatRecord(BaseModel):

    # Allow additional fields received from threat-intelligence APIs.
    model_config = ConfigDict(extra="allow")

    # Main threat indicator information.
    indicator: str = Field(min_length=1)

    indicator_type: Literal[
        "url",
        "domain",
        "ipv4",
        "ipv6"
    ]

    threat_type: str = Field(min_length=1)

    source: str = Field(min_length=1)

    # Optional timestamps and confidence score.
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None

    confidence: Optional[int] = Field(
        default=None,
        ge=0,
        le=100
    )

    # Remove unnecessary spaces from text fields.
    @field_validator("indicator", "threat_type", "source")
    @classmethod
    def strip_text(cls, value):
        return value.strip()

    # Normalize indicator type.
    @field_validator("indicator_type", mode="before")
    @classmethod
    def normalize_indicator_type(cls, value):
        if isinstance(value, str):
            return value.strip().lower()

        return value

    # Convert API timestamps such as:
    # 2026-11-05 00:32:05 UTC
    # into a datetime format Pydantic can understand.
    @field_validator("first_seen", "last_seen", mode="before")
    @classmethod
    def parse_feed_datetime(cls, value):

        if isinstance(value, str):
            value = value.strip()

            if value.endswith(" UTC"):
                value = value[:-4] + "+00:00"

        return value

    # Validate the indicator according to its declared type.
    @model_validator(mode="after")
    def validate_indicator(self):

        indicator = self.indicator

        # URL validation.
        if self.indicator_type == "url":

            parsed = urlparse(indicator)

            if parsed.scheme not in ("http", "https"):
                raise ValueError(
                    "URL must use HTTP or HTTPS"
                )

            if not parsed.hostname:
                raise ValueError(
                    "URL must contain a valid hostname"
                )

        # Domain validation.
        elif self.indicator_type == "domain":

            domain = indicator.rstrip(".")

            try:
                domain = domain.encode("idna").decode("ascii")
            except UnicodeError:
                raise ValueError("Invalid domain name")

            if len(domain) > 253:
                raise ValueError("Domain name is too long")

            labels = domain.split(".")

            for label in labels:

                if not re.fullmatch(
                    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?",
                    label
                ):
                    raise ValueError("Invalid domain name")

        # IPv4 and IPv6 validation.
        elif self.indicator_type in ("ipv4", "ipv6"):

            try:
                ip = ipaddress.ip_address(indicator)
            except ValueError:
                raise ValueError("Invalid IP address")

            if self.indicator_type == "ipv4" and ip.version != 4:
                raise ValueError("Expected an IPv4 address")

            if self.indicator_type == "ipv6" and ip.version != 6:
                raise ValueError("Expected an IPv6 address")

        return self
