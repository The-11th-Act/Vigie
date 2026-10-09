"""Import hors ligne des flux KEV, EPSS et des bulletins MSRC.

Une plateforme sans accès Internet sortant ne peut pas laisser le service beat
télécharger les flux. Les fichiers se récupèrent alors ailleurs, puis
s'appliquent ici, exactement comme le rafraîchissement quotidien les
appliquerait (mêmes garde-fous, même recalcul ciblé des findings) :

    https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
    https://epss.empiricalsecurity.com/epss_scores-current.csv.gz
    https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Sep  (un par mois, en JSON :
        curl -H "Accept: application/json" -o 2026-Sep.json <url>)

Usage :
    python -m scripts.import_threat_intel --kev kev.json --epss epss.csv.gz
    python -m scripts.import_threat_intel --msrc 2026-Aug.json 2026-Sep.json

    # Appliquer un instantané plus ancien que l'actuel, ou un catalogue KEV
    # nettement plus court que le précédent :
    python -m scripts.import_threat_intel --kev kev.json --force
"""

import argparse
import logging
import sys

from app.db.database import SessionLocal
from app.models.threat_intel import FEED_EPSS, FEED_KEV, FEED_MSRC
from app.parsers.threat_feeds import ThreatFeedError
from app.services.threat_intel import import_feed

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("import_threat_intel")


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Applique des fichiers KEV, EPSS ou MSRC téléchargés à part.",
    )
    parser.add_argument("--kev", metavar="FICHIER", help="catalogue KEV (JSON)")
    parser.add_argument("--epss", metavar="FICHIER", help="scores EPSS (CSV ou .csv.gz)")
    parser.add_argument(
        "--msrc",
        metavar="FICHIER",
        nargs="+",
        default=[],
        help="bulletins mensuels MSRC (CVRF en JSON), un fichier par mois",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="appliquer même un instantané plus ancien ou un catalogue rétréci",
    )
    args = parser.parse_args(argv)
    if not args.kev and not args.epss and not args.msrc:
        parser.error("indiquer au moins --kev, --epss ou --msrc")
    return args


def import_file(feed: str, path: str, force: bool) -> bool:
    """Retourne True si le fichier a été appliqué."""
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError as exc:
        logger.error("Lecture de %s impossible : %s", path, exc)
        return False

    db = SessionLocal()
    try:
        result = import_feed(db, feed, raw, force=force)
    except ThreatFeedError as exc:
        # Levée avant toute écriture : il n'y a rien à annuler.
        logger.error("%s non appliqué : %s", feed.upper(), exc)
        return False
    except Exception as exc:
        db.rollback()
        logger.error("Échec de l'import %s : %s", feed.upper(), exc)
        return False
    finally:
        db.close()

    if feed == FEED_MSRC:
        logger.info(
            "%s appliqué : %d remplacements de KB connus, %d liens de remédiation "
            "reportés sur un KB plus récent.",
            path,
            result.records,
            result.changed,
        )
        return True
    logger.info(
        "%s appliqué : %d entrées, %d CVE modifiés, %d findings recalculés.",
        feed.upper(),
        result.records,
        result.changed,
        result.rescored,
    )
    return True


def main(argv=None) -> int:
    args = parse_args(argv)
    # Chaque fichier réussit ou échoue seul, comme pour le rafraîchissement réseau.
    files = [(FEED_KEV, args.kev), (FEED_EPSS, args.epss)]
    files += [(FEED_MSRC, path) for path in args.msrc]
    outcomes = [import_file(feed, path, args.force) for feed, path in files if path]
    return 0 if all(outcomes) else 1


if __name__ == "__main__":
    sys.exit(main())
