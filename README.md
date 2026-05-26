# Sentinel

Application web (PWA) anti-arnaque. **100% local**, aucune donnée collectée.

## Comment ça marche

1. L'utilisateur colle un SMS, email, numéro ou lien dans l'app.
2. L'analyse est faite **uniquement sur son téléphone** (règles regex + cache d'arnaques connues).
3. L'app affiche un verdict : **arnaque probable** / **suspect** / **OK** avec les raisons.

L'app ne bloque rien — c'est une aide à la décision. L'utilisateur reste seul juge.

## Hébergement

PWA statique servie via GitHub Pages :
`https://nefesec.github.io/sentinel/`

Toute requête réseau est limitée à un GET anonyme du `scams.json` toutes les 6h.

## Mise à jour des arnaques

Éditer `scams.json`, commit + push → déployé en 30s par GitHub Pages.

```bash
# Ajouter une nouvelle alerte → édit scams.json
git add scams.json && git commit -m "alerte: nouvelle arnaque XYZ" && git push
```

Toutes les apps fetch cette liste dans les 6h.

## Structure

```
sentinel/
├── index.html       — UI (3 onglets : Scanner / Arnaques en cours / À propos)
├── app.js           — Logique UI + analyse + fetch
├── rules.js         — Règles de détection (regex) embarquées
├── scams.json       — Liste actuelle des arnaques (fetch périodique)
├── manifest.json    — PWA manifest (icône, nom, couleurs)
├── sw.js            — Service Worker (cache offline)
├── icons/           — Icônes app
└── LICENSE          — Tous droits réservés
```

## Licence

Voir `LICENSE`. **Code et marque non réutilisables sans autorisation écrite.**

## Responsabilité

Aucune garantie de détection. L'utilisateur reste seul responsable. Voir LICENSE.
