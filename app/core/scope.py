"""Scopes: which hosts a user may see and act on.

A scope is a set of teams (``Asset.owner_team``). A user with teams assigned
(``user_teams``) sees only the hosts of those teams, and everything attached
to them (findings, fixes, tickets, CVEs, figures), on every screen, export and
extract. A user without any, and an administrator, sees the whole estate.

Actions that reach past any one team are refused to a scoped user: uploading a
scan (its ingestion creates hosts and closes findings wherever it covers),
editing the CVE catalogue (a score moves every team's risk).

"" stands for hosts without a team, as in backlog_snapshots; the API spells it
NOT_SET ("__none__"), like the filters.
"""

from dataclasses import dataclass

from fastapi import Depends, HTTPException, status
from sqlalchemy import false, or_
from sqlalchemy.orm import Session

from app.core.modules import current_user
from app.db.database import get_db
from app.models.asset import Asset
from app.models.user import User, UserTeam
from app.models.vulnerability import AssetVulnerability, Vulnerability

ROLE_ADMIN = "admin"
NO_TEAM = ""
NOT_SET = "__none__"


@dataclass(frozen=True)
class Scope:
    # None: the whole estate.
    teams: frozenset[str] | None = None

    @property
    def restricted(self) -> bool:
        return self.teams is not None

    def assets(self, column=Asset.owner_team):
        """SQL condition on a team column: true for the teams in scope.

        To be added to any query reading hosts or what hangs off them; a
        no-op for an unrestricted scope.
        """
        if self.teams is None:
            return None
        named = sorted(team for team in self.teams if team != NO_TEAM)
        clauses = [column.in_(named)] if named else []
        if NO_TEAM in self.teams:
            clauses += [column.is_(None), column == NO_TEAM]
        return or_(*clauses) if clauses else false()

    def filter(self, query, column=Asset.owner_team):
        """``query`` restricted to the scope (the query must join Asset)."""
        clause = self.assets(column)
        return query if clause is None else query.filter(clause)

    def filter_vulnerabilities(self, db: Session, query, column=None):
        """``query`` on CVEs restricted to those found on a host in scope.

        The catalogue is shared, but which CVEs exist says what another team's
        hosts are exposed to.
        """
        if self.teams is None:
            return query
        found = (
            db.query(AssetVulnerability.vulnerability_id)
            .join(Asset, Asset.id == AssetVulnerability.asset_id)
            .filter(self.assets())
        )
        return query.filter((column or Vulnerability.id).in_(found))

    def allows(self, team: str | None) -> bool:
        return self.teams is None or (team or NO_TEAM) in self.teams

    def visible_teams(self, teams) -> list:
        """The team names of a list that this scope may show."""
        if self.teams is None:
            return list(teams)
        return [team for team in teams if (team or NO_TEAM) in self.teams]

    def refuse_if_restricted(self, action: str) -> None:
        """For an action that reaches past any one team."""
        if self.restricted:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"{action} affects every team: not available to a scoped account",
            )


EVERYTHING = Scope()


def scope_of(db: Session, user: User) -> Scope:
    if user.role == ROLE_ADMIN:
        return EVERYTHING
    teams = {row.owner_team for row in db.query(UserTeam).filter_by(user_id=user.id)}
    return Scope(frozenset(teams)) if teams else EVERYTHING


def current_scope(
    user: User = Depends(current_user), db: Session = Depends(get_db)
) -> Scope:
    """The scope of the signed-in user, read from the database each request."""
    return scope_of(db, user)


def team_value(api_value: str | None) -> str:
    """A team as the API names it (NOT_SET for none) to its stored form."""
    return NO_TEAM if api_value in (None, "", NOT_SET) else api_value


def api_team(stored: str) -> str:
    return NOT_SET if stored == NO_TEAM else stored
