/**
 * Sentinel — règles de détection locales.
 * Mises à jour : édite ce fichier OU pousse de nouvelles entrées dans scams.json
 * (qui prend le pas dynamiquement via le fetch toutes les 6h).
 *
 * Score :
 *   +3 = signal fort (forte présomption d'arnaque)
 *   +2 = signal moyen
 *   +1 = signal faible (à corréler)
 *
 * Verdict :
 *   score >= 5 → DANGER (arnaque probable)
 *   score 2-4  → SUSPECT (vigilance)
 *   score 0-1  → OK
 */

const RULES = {

  // ────── Mots-clés d'arnaques classiques (SMS / mail) ──────
  keywords: [
    // Urgence / menace
    { re: /\b(urgent|imm[ée]diat|derni(er|ère)\s+(rappel|chance|d[ée]lai)|sous\s+\d+\s*(heures?|jours?))\b/i, score: 2, reason: 'Sentiment d\'urgence ou de menace (procédé classique d\'arnaque)' },
    { re: /\b(suspendu|bloqu[ée]|d[ée]sactiv[ée]|gel[ée]|fraude\s+d[ée]tect[ée])\b/i, score: 2, reason: 'Menace de blocage de compte / service (technique de manipulation)' },
    { re: /\b(amende|condamnation|poursuite|huissier|police|gendarmerie|justice)\b.{0,40}\b(payer|r[ée]gler|cliquer|formulaire)\b/i, score: 3, reason: 'Mention d\'autorité légale combinée à une demande de paiement / action' },

    // Argent / cadeau / faux héritage
    { re: /\b(h[ée]rit(age|er|i[èe]re)|million(s)?\s+d['e]?\s*euros?|loterie|gagn[ée]|cadeau|gain)\b/i, score: 3, reason: 'Fausse promesse d\'argent / héritage / gain' },
    { re: /\b(bitcoin|crypto|investiss?ement|rendement|trading)\b.{0,40}\b(garanti|s[ûu]r|sans\s+risque)\b/i, score: 3, reason: 'Promesse de gain garanti (impossible en investissement réel)' },

    // Faux services / livraisons
    { re: /\b(colis|livraison|chronopost|dpd|la\s*poste|laposte|ups|fedex|amazon)\b.{0,50}\b(frais|douane|taxe|adresse|relais)\b/i, score: 3, reason: 'Arnaque colis : faux frais de livraison / mauvaise adresse' },
    { re: /\b(impôts?|finances?\s+publiques?|remboursement|tr[ée]sor\s+public)\b/i, score: 2, reason: 'Faux email/SMS impôts (très courant — les impôts ne demandent JAMAIS d\'infos par SMS)' },
    { re: /\b(s[ée]curit[ée]\s+sociale|cpam|ameli|carte\s+vitale)\b.{0,50}\b(mise\s*à\s*jour|renouv|formulaire|cliquer)\b/i, score: 3, reason: 'Faux SMS sécurité sociale / Ameli' },
    { re: /\b(EDF|engie|enedis|gdf|GRDF)\b.{0,50}\b(facture|coupure|impay[ée]|paiement)\b/i, score: 2, reason: 'Faux email fournisseur d\'énergie' },

    // Banque / paiement
    { re: /\b(carte\s+(bleue|bancaire|de\s+cr[ée]dit)|virement|d[ée]bit|3-?D\s*secure|fraude\s+bancaire)\b/i, score: 2, reason: 'Référence bancaire — vérifie sur l\'app/site officielle de ta banque, jamais via le lien du message' },
    { re: /\b(iban|code\s+(secret|confidentiel|pin|otp)|cvv|cryptogramme)\b/i, score: 3, reason: 'Demande d\'informations bancaires sensibles — un service légitime ne demande JAMAIS ça par SMS/mail' },

    // Captures de compte
    { re: /\b(mot\s+de\s+passe|identifiant|connexion\s+suspecte|confirm[ée]\s+(votre|ton)\s+compte)\b/i, score: 2, reason: 'Tentative de vol d\'identifiants' },
  ],

  // ────── URL : motifs suspects ──────
  urlPatterns: [
    { re: /https?:\/\/(?:[\w-]+\.)*(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|ow\.ly|s\.id|cutt\.ly|rb\.gy|rebrand\.ly|tiny\.cc)\//i, score: 2, reason: 'Lien raccourci — l\'URL réelle est cachée (utilisé par 95% des arnaques)' },
    { re: /https?:\/\/[\w-]+\.(?:top|xyz|click|loan|win|stream|gq|tk|cf|ml|ga)\//i, score: 3, reason: 'Extension de domaine très suspecte (rarement utilisée par les vrais sites)' },
    { re: /https?:\/\/(?:\d{1,3}\.){3}\d{1,3}/i, score: 3, reason: 'URL avec adresse IP directe au lieu d\'un nom de domaine (très suspect)' },
    { re: /https?:\/\/[^\/]*(?:laposte?|amazone|chronopost|sosh-mobile|orang3|fre3|sfrr|paypa1|micros0ft|g00gle|apple-?id-?login|netf1ix)/i, score: 3, reason: 'Faux domaine imitant un site connu (typosquat)' },
    { re: /https?:\/\/[^\/]*\.(?:fr|com|net)\.(?:[a-z]{2,4})/i, score: 2, reason: 'Double extension (.fr.xyz par exemple) — domaine truqué' },
    { re: /https?:\/\/[^\/]{0,15}-(?:secure|verify|update|confirm|alert|login)/i, score: 2, reason: 'Sous-domaine contenant "secure/verify/update" — pattern fréquent de phishing' },
  ],

  // ────── Numéros de téléphone : préfixes / patterns suspects ──────
  phonePatterns: [
    { re: /^(\+?33|0)?\s*8(?:99|98|97|96|95)/i, score: 3, reason: 'Numéro surtaxé (08 99 / 08 98) — coûte cher à l\'appel' },
    { re: /^(\+?33|0)?\s*0?89\d/i, score: 2, reason: 'Préfixe 089X souvent surtaxé' },
    { re: /^(\+?(?!33|44|32|41|49|34|39|45|31|351|352)[0-9]{3,})/i, score: 2, reason: 'Numéro international hors zone européenne courante — arnaque "wangiri" probable' },
    { re: /^(\+?33|0)?\s*[1-9][\s.-]?\d[\s.-]?\d[\s.-]?\d[\s.-]?\d$/i, score: 0, reason: 'Format français valide (à vérifier en contexte)' },
  ],

  // ────── Combos qui amplifient ──────
  combos: [
    { triggers: ['banque', 'cliquez'], score: 2, reason: 'Banque + lien cliquable : aucune banque sérieuse ne fait ça par SMS' },
    { triggers: ['gendarmerie', 'amende'], score: 3, reason: 'L\'État ne réclame jamais d\'amende par SMS avec lien' },
  ],
};

// Détection légère du type d'input pour adapter les messages
function detectInputType(text) {
  const t = text.trim();
  if (/^[\+\d\s.\-()]{6,20}$/.test(t)) return 'phone';
  if (/^https?:\/\//i.test(t) && t.split(/\s+/).length === 1) return 'url';
  if (/@[\w.-]+\.[a-z]{2,}/i.test(t) && t.length < 100) return 'email';
  return 'message';  // SMS / mail / texte libre
}
