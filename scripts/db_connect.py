import logging
import os
from contextlib import contextmanager
from pathlib import Path

from dotenv import load_dotenv
from neo4j import GraphDatabase
from neo4j.exceptions import AuthError, ServiceUnavailable

load_dotenv(dotenv_path=Path(__file__).resolve().parents[1] / ".env")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("sentinel.db")

_NEO4J_URI = os.getenv("NEO4J_URI")
_NEO4J_USERNAME = os.getenv("NEO4J_USERNAME")
_NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")
_NEO4J_DATABASE = os.getenv("NEO4J_DATABASE", "neo4j")


def get_driver():
    if not all([_NEO4J_URI, _NEO4J_USERNAME, _NEO4J_PASSWORD]):
        raise EnvironmentError(
            "Missing required env vars: NEO4J_URI, NEO4J_USERNAME, NEO4J_PASSWORD"
        )
    try:
        driver = GraphDatabase.driver(
            _NEO4J_URI,
            auth=(_NEO4J_USERNAME, _NEO4J_PASSWORD),
        )
        driver.verify_connectivity()
        logger.info("Connected to Neo4j at %s", _NEO4J_URI)
        return driver
    except AuthError as e:
        logger.error("Neo4j authentication failed: %s", e)
        raise
    except ServiceUnavailable as e:
        logger.error("Neo4j service unavailable: %s", e)
        raise


@contextmanager
def get_session(driver=None):
    _driver = driver or get_driver()
    _owns_driver = driver is None
    try:
        with _driver.session(database=_NEO4J_DATABASE) as session:
            yield session
    finally:
        if _owns_driver:
            _driver.close()
