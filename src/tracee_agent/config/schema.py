"""Schéma de configuration de l'agent (validé par Pydantic)."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ServerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")  # rejette les champs inconnus (typos)
    url: str
    token: str


class CaptureConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    default_interface: str | None = None
    # 1600 : couvre une trame Ethernet à MTU pleine (1514) + marge VLAN, pour
    # capturer tout le ClientHello TLS / la requête DNS sans tronquer le SNI ;
    # reste loin des 65535 pour ne pas capturer les gros transferts en entier.
    snaplen: int = Field(default=1600, gt=0)  # > 0 sinon erreur


class LoggingConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    file: str | None = None


class AgentConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    server: ServerConfig
    capture: CaptureConfig = CaptureConfig()
    logging: LoggingConfig = LoggingConfig()
