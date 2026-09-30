// How the API names "hosts without a team" in a scope (app/core/scope.py).
export const NO_TEAM = '__none__'

export function teamLabel(team) {
  return team === NO_TEAM ? 'Hosts without a team' : team
}

// A scope as one line: null is the whole estate.
export function scopeLabel(teams) {
  if (!teams || teams.length === 0) return 'Whole estate'
  return teams.map(teamLabel).join(', ')
}
