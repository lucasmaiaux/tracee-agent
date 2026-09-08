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
    # 4096 : il faut tenir un ClientHello entier, seul porteur du SNI. Une trame
    # Ethernet pleine (1514) n'y suffit plus — l'échange de clés post-quantique
    # (X25519MLKEM768) porte le ClientHello des navigateurs à ~2000 octets, que la
    # segmentation déléguée à la carte (TSO/LSO) livre d'un seul bloc à la capture.
    # Reste loin des 65535 pour ne pas capturer les gros transferts en entier.
    snaplen: int = Field(default=4096, gt=0)  # > 0 sinon erreur


class LoggingConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    file: str | None = None


class AgentConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    server: ServerConfig
    capture: CaptureConfig = CaptureConfig()
    logging: LoggingConfig = LoggingConfig()
