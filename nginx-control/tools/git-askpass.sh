#!/bin/sh
# Aide à l'authentification git (GIT_ASKPASS) : fournit le jeton quand git le redemande,
# notamment après une redirection du forge (git n'y renvoie pas les identifiants de l'URL).
# Le jeton ne vit que dans l'environnement du processus git (NGX_GIT_TOKEN) ; il n'est servi
# que pour l'hôte du dépôt configuré (NGX_GIT_HOST), jamais pour un autre domaine.
case "$1" in
  *"$NGX_GIT_HOST"*) ;;
  *) exit 1 ;;
esac
case "$1" in
  Username*) printf '%s\n' "$NGX_GIT_TOKEN" ;;
  *) printf '\n' ;;
esac
