"""Création (ou promotion) du premier administrateur.

Le bootstrap automatique au démarrage exige que ``ADMIN_USERNAME`` /
``ADMIN_EMAIL`` / ``ADMIN_PASSWORD`` restent dans l'environnement du service.
En production, c'est un mot de passe administrateur exposé en permanence dans
l'environnement d'un conteneur qui tourne 24h/24, alors que l'opération est
ponctuelle. Ce script permet de la faire une fois, puis de l'oublier.

Usage :
    python -m scripts.create_admin --username admin --email admin@example.com
    # le mot de passe est demandé de manière interactive, jamais en argument
    # (un argument de ligne de commande finit dans l'historique du shell et
    # dans la table des processus)

    # Non interactif (CI, provisionnement) :
    ADMIN_PASSWORD='...' python -m scripts.create_admin \
        --username admin --email admin@example.com --password-from-env
"""

import argparse
import getpass
import logging
import os
import sys

from pydantic import ValidationError
from sqlalchemy import or_

from app.core.security import get_password_hash
from app.db.database import SessionLocal
from app.models.user import User
from app.schemas.user import UserCreate

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("create_admin")


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Crée ou promeut un compte administrateur.",
    )
    parser.add_argument("--username", required=True)
    parser.add_argument("--email", required=True)
    parser.add_argument(
        "--password-from-env",
        action="store_true",
        help=(
            "Lire le mot de passe dans ADMIN_PASSWORD au lieu de le demander. "
            "Pour les contextes non interactifs uniquement."
        ),
    )
    return parser.parse_args(argv)


def read_password(from_env: bool) -> str:
    if from_env:
        password = os.environ.get("ADMIN_PASSWORD", "")
        if not password:
            logger.error("--password-from-env demandé mais ADMIN_PASSWORD est vide.")
            raise SystemExit(2)
        return password

    password = getpass.getpass("Mot de passe administrateur : ")
    confirmation = getpass.getpass("Confirmer : ")
    if password != confirmation:
        logger.error("Les deux saisies diffèrent.")
        raise SystemExit(2)
    return password


def create_admin(username: str, email: str, password: str) -> int:
    """Retourne un code de sortie : 0 si tout va bien, 1 sinon."""
    try:
        # Réutilise la validation de l'inscription (format d'email, longueur et
        # complexité du mot de passe) plutôt que de la dupliquer.
        credentials = UserCreate(email=email, username=username, password=password)
    except ValidationError as exc:
        logger.error("Identifiants invalides : %s", exc)
        return 1

    db = SessionLocal()
    try:
        existing = (
            db.query(User)
            .filter(
                or_(
                    User.username == credentials.username,
                    User.email == credentials.email,
                )
            )
            .first()
        )

        if existing:
            if existing.role == "admin":
                logger.info("'%s' est déjà administrateur.", existing.username)
                return 0
            existing.role = "admin"
            db.commit()
            logger.info("'%s' a été promu administrateur.", existing.username)
            return 0

        admin = User(
            email=credentials.email,
            username=credentials.username,
            hashed_password=get_password_hash(credentials.password),
            role="admin",
        )
        db.add(admin)
        db.commit()
        logger.info("Administrateur '%s' créé.", admin.username)
        return 0
    except Exception as exc:
        db.rollback()
        logger.error("Échec de la création : %s", exc)
        return 1
    finally:
        db.close()


def main(argv=None) -> int:
    args = parse_args(argv)
    password = read_password(args.password_from_env)
    return create_admin(args.username, args.email, password)


if __name__ == "__main__":
    sys.exit(main())
