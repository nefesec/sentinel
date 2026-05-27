/**
 * Sentinel — moteur de détection locale.
 *
 * Score :
 *   +4 = signal très fort (à lui seul = ARNAQUE PROBABLE)
 *   +3 = signal fort
 *   +2 = signal moyen (à corréler avec d'autres)
 *   +1 = signal faible (couleur de contexte)
 *
 * Verdict :
 *   ≥ 6 → DANGER (arnaque probable)
 *   3-5 → ATTENTION (méfiance recommandée)
 *   0-2 → CLEAR (aucun signal connu)
 */

const RULES = {

  // ────── KEYWORDS : phrases / motifs textuels ──────
  keywords: [
    // ─── Urgence et pression psychologique ───
    { re: /\b(urgent|imm[ée]diat(?:ement)?|de\s*toute\s*urgence|sous\s+(?:\d+|quelques?|24|48|72)\s*(?:h(?:eures?)?|min(?:utes?)?|jours?))\b/i,
      score: 2, reason: 'Procédé d\'urgence — pression psychologique typique des arnaques' },
    { re: /\b(derni(?:er|ère)\s+(?:rappel|chance|avis|notification|d[ée]lai|tentative))\b/i,
      score: 3, reason: 'Mention de « dernier rappel » : technique de manipulation par peur' },
    { re: /\b(avant\s+(?:huissier|saisie|poursuite|contentieux|justice|gendarmerie|police))\b/i,
      score: 4, reason: 'Menace d\'huissier ou de poursuites — JAMAIS par SMS/email avec lien' },
    { re: /\b(suspendu|bloqu[ée]|d[ée]sactiv[ée]|verrouill[ée]|gel[ée]|r[ée]siliation|fraude\s+d[ée]tect[ée]|action\s+requise|connexion\s+suspecte)\b/i,
      score: 2, reason: 'Menace de blocage / compromission de compte' },

    // ─── Faux services publics ───
    { re: /\b(?:impôts?|tr[ée]sor\s+public|finances?\s+publiques?|dgfip|antai|amende[s]?|infraction|stationnement)\b.{0,80}\b(?:r[ée]gler|payer|cliquer|lien|formulaire|attach|pi[èe]ce\s+jointe)\b/i,
      score: 4, reason: 'Faux SMS/mail Trésor Public ou Amendes — ne demandent JAMAIS de paiement par lien' },
    { re: /\b(s[ée]curit[ée]\s+sociale|cpam|ameli|carte\s+vitale|caf|allocations|p[oô]le\s+emploi|france\s+travail|cpf|moncompteformation)\b.{0,60}\b(?:mise\s*à\s*jour|renouv|actualisation|formulaire|attestation|cliquer|lien|http|app|reconfirmer)\b/i,
      score: 4, reason: 'Faux service public (Ameli/CAF/CPF/France Travail) — aucun de ces services ne demande ça par SMS' },

    // ─── Faux colis / livraison ───
    { re: /\b(colis|livraison|exp[ée]dition|paquet|courrier)\b.{0,80}\b(?:frais|douane|taxe|adresse|relais|attente|retenu|red[ée]livrance|r[ée]exp[ée]dition|stockage)\b/i,
      score: 3, reason: 'Arnaque colis : faux frais de livraison, douane ou adresse incomplète' },
    { re: /\b(chronopost|dpd|gls|ups|fedex|colissimo|colis\s*priv[ée]|mondial\s*relay|relais\s*colis|laposte|la\s+poste|amazon\s+log|tnt)\b.{0,60}\b(?:http|cliquer|lien|r[ée]gler|frais|tracking|suivi)/i,
      score: 4, reason: 'Imitation de transporteur connu — aucun transporteur légitime n\'envoie d\'SMS avec lien de paiement' },

    // ─── Banque / paiement ───
    { re: /\b(carte\s+(?:bleue|bancaire|de\s+cr[ée]dit|vitale)|virement|d[ée]bit|pr[ée]l[èe]vement|3[\s-]?d[\s-]?secure|3ds|fraude\s+bancaire|op[ée]ration\s+suspecte|paiement\s+(?:initi[ée]|en\s+attente|refus[ée]))\b/i,
      score: 2, reason: 'Référence bancaire — vérifie TOUJOURS via l\'app officielle de ta banque, jamais via le lien' },
    { re: /\b(?:bnp|soci[ée]t[ée]\s*g[ée]n[ée]rale|cr[ée]dit\s*(?:agricole|mutuel|du\s*nord|coop[ée]ratif|lyonnais)|cic|lcl|caisse\s*d['eé]?\s*[ée]pargne|banque\s*postale|hello\s*bank|fortuneo|boursorama|n26|revolut|qonto|paypal|orange\s*bank)\b/i,
      score: 1, reason: 'Mention d\'établissement bancaire (vérifier qui envoie réellement)' },
    { re: /\b(iban|bic|swift|code\s+(?:secret|confidentiel|pin|otp|sms|à\s*usage\s*unique)|cvv|crypto[\s-]?gramme|num[ée]ro\s+de\s+carte|date\s+expiration)\b/i,
      score: 4, reason: 'Demande d\'infos bancaires sensibles — AUCUN service légitime ne demande ça par message' },

    // ─── Vol d'identifiants / phishing direct ───
    { re: /\b(mot\s+de\s+passe|identifiant|mdp|password|login|connexion\s+(?:depuis|à\s+partir)|nouvel\s+appareil|confirm(?:ation|er)\s+(?:de\s+)?(?:ton|votre)\s+(?:compte|identit[ée]))\b/i,
      score: 2, reason: 'Tentative de vol d\'identifiants — un service légitime ne te fait jamais reconfirmer par lien' },
    { re: /\b(?:micros[o0]ft|appl[e3]?|i[\s-]?cloud|gma[il1]+|outlook|netflix|spot[iy]fy|amaz[o0]n|dropbox|paypal|disn[e3]y\s*\+?|prime\s+video)\b.{0,60}\b(?:suspendu|bloqu[ée]|expir[ée]|connexion|verifier|confirm|valider|cliquer)\b/i,
      score: 3, reason: 'Phishing imitant un service grand public' },

    // ─── Argent facile / cadeau / héritage ───
    { re: /\b(h[ée]rit(?:age|er|i[èe]re)|notaire\s+(?:de\s+)?[a-z]+|million(?:s)?\s+d['e]?\s*(?:euros?|dollars?)|loterie|gagn[ée]|tir[ée]\s+au\s+sort|f[ée]licitations?|cadeau|prime|gain|jackpot|cagnotte)\b/i,
      score: 3, reason: 'Fausse promesse d\'argent gratuit, héritage ou gain' },
    { re: /\b(?:crypto|bitcoin|ethereum|nft|trading|forex|investiss?ement|placement|rendement|trader)\b.{0,80}\b(?:garanti|s[ûu]r|sans\s+risque|sans\s+perte|x\s*\d+|\d+%\s+par\s+(?:jour|mois|semaine)|doublez|triplez)\b/i,
      score: 4, reason: 'Promesse de gain garanti en crypto/trading — c\'est mathématiquement impossible' },

    // ─── Faux conseiller / arnaque vocale ───
    { re: /\b(conseill[èe]r|service\s+(?:client|fraude|s[ée]curit[ée])|agent|technicien|support|hotline)\b.{0,60}\b(?:appel|t[ée]l[ée]phon|contact|joindre|rappel)\b/i,
      score: 2, reason: 'Mention d\'un soi-disant « conseiller » — vérifier en rappelant le numéro officiel' },

    // ─── Compte personnel de formation (gros sujet 2024-2026) ───
    { re: /\b(cpf|moncompteformation|compte\s+personnel\s+de\s+formation|formation\s+(?:offerte|gratuite|finan[cç][ée]e))\b/i,
      score: 3, reason: 'Démarchage CPF — depuis 2022 le démarchage CPF est INTERDIT, c\'est forcément une arnaque' },

    // ─── Énergie / fournisseurs ───
    { re: /\b(?:edf|engie|enedis|gdf|grdf|total\s*[ée]nergie|eni|direct\s*[ée]nergie)\b.{0,80}\b(?:facture|coupure|impay[ée]|relance|paiement|remboursement)\b/i,
      score: 3, reason: 'Faux mail/SMS fournisseur d\'énergie' },

    // ─── France Connect / impôts / CAF (sigles officiels imités) ───
    { re: /\b(franceconnect|france\s*connect|gouv\.fr|service[\s-]public|elysee|premier\s+ministre|cnam|secu)\b/i,
      score: 1, reason: 'Mention d\'organisme public — vérifier l\'expéditeur réel (jamais le lien)' },

    // ─── Demandes inhabituelles ───
    { re: /\b(?:envoy(?:er|ez)|transf(?:[ée]rer|ert)|don[\s-]?moi|partager)\s+(?:moi\s+)?(?:le|ce|un)\s*(?:code|sms|otp|num[ée]ro)\b/i,
      score: 4, reason: 'Demande de transmission d\'un code reçu par SMS — c\'est ce que font les escrocs pour voler ton compte' },
    { re: /\b(?:carte\s*cadeau|gift\s*card|google\s*play|paysafecard|steam|amazon\s*pay|coupon\s*pcs)\b/i,
      score: 3, reason: 'Demande de paiement en cartes prépayées — méthode favorite des escrocs (intraçable)' },

    // ─── Sextorsion / chantage ───
    { re: /\b(?:webcam|cam[ée]ra|vid[ée]o\s+intime|enregistr[ée]|piratage|j['e]?\s*ai\s+acc[èe]s\s+(?:à\s+)?(?:ton|votre))\b.{0,80}\b(?:bitcoin|payer|silence|diffuser|envoyer|publier)\b/i,
      score: 4, reason: 'Sextorsion : ils n\'ont aucune vidéo, c\'est un bluff. NE PAYEZ JAMAIS' },

    // ─── Arnaque romance / sentiment ───
    { re: /\b(?:rencontr[ée]|tinder|meetic|badoo|seul[e]?|veuf|veuve|militaire\s+(?:am[ée]ricain|en\s+mission)|chirurgien|ing[ée]nieur\s+(?:offshore|plateforme))\b.{0,100}\b(?:aide|argent|virement|bloqu[ée]|coffre|h[ée]rit)/i,
      score: 4, reason: 'Arnaque romance / brouteur — schéma classique de relation virtuelle qui demande de l\'argent' },
  ],

  // ────── URL : patterns suspects ──────
  urlPatterns: [
    // Raccourcisseurs (anonymisation)
    { re: /https?:\/\/(?:[\w-]+\.)*(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|ow\.ly|s\.id|cutt\.ly|rb\.gy|rebrand\.ly|tiny\.cc|short\.io|t\.ly|lnkd\.in|buff\.ly|adf\.ly)\//i,
      score: 3, reason: 'Lien raccourci — l\'URL réelle est cachée (95% des arnaques l\'utilisent)' },

    // TLDs douteux (rarement utilisés par les vrais sites)
    { re: /https?:\/\/[\w.-]+\.(?:top|xyz|click|loan|win|stream|gq|tk|cf|ml|ga|men|date|country|review|trade|kim|biz|info|online|site|store|space|website|tech|life)\b/i,
      score: 3, reason: 'Extension de domaine suspecte (.top, .xyz, .click, etc.) — rarement utilisée par les vrais services' },

    // IP directe au lieu d'un domaine
    { re: /https?:\/\/(?:\d{1,3}\.){3}\d{1,3}(?:[\/:]|$)/i,
      score: 4, reason: 'URL avec adresse IP au lieu d\'un nom de domaine — extrêmement suspect' },

    // Typosquat de marques connues
    { re: /https?:\/\/[^\s\/]*(?:laposte?[\s.-]?fr|amazon[e0]|chr[o0]nopost|s[o0]sh-?mobile|orange[3]|free[3]|sfr[r]|bouygues?-?tel|paypa[l1]|micr[o0]s[o0]ft|g[o0]{2}gle|app[l1]e-?id|netf[l1]ix|impots?\.gouv|amel[i1l]|caf[\s.-]|cpam|france-?connect)/i,
      score: 4, reason: 'Faux domaine imitant une marque/service connu (typosquat caractères remplacés)' },

    // Double TLD (laposte.fr.xyz)
    { re: /https?:\/\/[^\/]*\.(?:fr|com|net|org|gouv)\.(?:[a-z]{2,5})(?:\/|$)/i,
      score: 4, reason: 'Double extension (.fr.xxx) — l\'URL est trompeuse, le vrai domaine est la dernière partie' },

    // Sous-domaines suspects
    { re: /https?:\/\/(?:secure|verify|update|confirm|alert|login|account|auth|security|service|client|portal|access)[\w.-]*\.(?:top|xyz|click|loan|win|stream|gq|tk|cf|ml|ga|info|online|site|app|com)/i,
      score: 3, reason: 'Sous-domaine "secure/verify/login..." sur TLD douteux — pattern de phishing' },

    // Subdomain bourré de tirets (suspect)
    { re: /https?:\/\/[\w-]*(?:-(?:[\w]+))(?:-[\w]+){2,}\./i,
      score: 2, reason: 'Domaine avec beaucoup de tirets — souvent fabriqué pour imiter un vrai' },

    // Encodage punycode (xn--)
    { re: /https?:\/\/(?:[\w.-]+\.)?xn--/i,
      score: 3, reason: 'Domaine encodé en Punycode — utilisé pour imiter visuellement un vrai (caractères Unicode/cyrillic)' },

    // URL longue et obfusquée
    { re: /https?:\/\/\S{120,}/i,
      score: 2, reason: 'URL très longue — souvent utilisée pour cacher la vraie destination' },
  ],

  // ────── PHONE : préfixes et patterns ──────
  phonePatterns: [
    // Numéros surtaxés français
    { re: /^(?:\+?33|0)?\s*8(?:99|98|97|96|95)/i,
      score: 4, reason: 'Numéro surtaxé (08 99 / 08 98 / 08 97) — coûte 0,80-2,99 €/min ou 0,80-3€/appel' },
    { re: /^(?:\+?33|0)?\s*0?89\d/i,
      score: 3, reason: 'Préfixe 089X — souvent surtaxé' },

    // Numéros internationaux exotiques (wangiri)
    // Côte d'Ivoire, Ghana, Burkina, Sénégal, Tunisie, etc. → souvent wangiri
    { re: /^\+(?:225|233|228|221|216|212|234|242|244|256|260|263|264|216|353|389|371)\b/i,
      score: 3, reason: 'Numéro international d\'une zone fréquemment associée aux arnaques wangiri — ne rappelle pas' },

    // Tout numéro international non européen courant
    { re: /^\+(?!33|44|32|41|49|34|39|45|31|351|352|420|420|36|46|47|48|358|371|372|370|353|30|357|356|354|385|386|423|377|378|39\.)\d{2,3}/,
      score: 2, reason: 'Numéro international hors zone européenne courante — méfiance, possible wangiri' },

    // Numéro français mobile / fixe / VoIP (info contextuelle, pas score)
    { re: /^(?:\+?33|0)?\s*[67]/,
      score: 0, reason: 'Numéro français mobile' },
    { re: /^(?:\+?33|0)?\s*9/,
      score: 1, reason: 'Numéro français 09 (VoIP) — souvent utilisé par escrocs car peu cher' },
  ],

  // ────── EMAIL : domaine expéditeur ──────
  emailPatterns: [
    // Domaines free email utilisés pour usurper
    { re: /@(?:gmail|outlook|hotmail|yahoo|live|free|wanadoo|orange|laposte|sfr|gmx)\.(?:com|fr|net)\b/i,
      score: 1, reason: 'Email envoyé depuis un domaine grand public (gmail, outlook...) — un vrai service utilise toujours son propre domaine' },
    // Mention d'un service officiel dans l'email mais domaine free
    { re: /(?:impots?|ameli|caf|edf|engie|laposte|chronopost|bnp|cic|lcl)[\w.-]*@(?:gmail|outlook|hotmail|yahoo|live)\.(?:com|fr)/i,
      score: 4, reason: 'Email prétend venir d\'un organisme officiel mais envoyé depuis un domaine perso (gmail/outlook) → arnaque évidente' },
  ],

  // ────── COMBOS : amplifient le score quand plusieurs signaux ──────
  combos: [
    { triggers: ['banque', 'cliquez'], score: 3,
      reason: 'Banque + lien cliquable : aucune banque sérieuse ne fait ça par SMS/email' },
    { triggers: ['gendarmerie', 'amende'], score: 4,
      reason: 'L\'État ne réclame jamais d\'amende par message avec lien — c\'est forcément faux' },
    { triggers: ['impôts', 'remboursement'], score: 4,
      reason: 'Faux remboursement d\'impôts : impots.gouv.fr ne fonctionne JAMAIS par mail/SMS avec lien' },
    { triggers: ['colis', 'frais'], score: 3,
      reason: 'Colis + frais à payer = arnaque colis (Chronopost, La Poste, Mondial Relay sont imités)' },
    { triggers: ['vinted', 'lien'], score: 3,
      reason: 'Vinted + lien externe pour "confirmer la livraison" = arnaque acheteur très répandue' },
    { triggers: ['urgent', 'cliquer'], score: 2,
      reason: 'Urgence + lien = combo classique pour faire cliquer sans réfléchir' },
    { triggers: ['compte', 'suspendu', 'cliquer'], score: 3,
      reason: 'Compte suspendu + lien = phishing classique' },
  ],
};

// ────── Détection du type d'entrée ──────
function detectInputType(text) {
  const t = text.trim();
  if (/^[\+\d\s.\-()]{6,20}$/.test(t)) return 'phone';
  if (/^https?:\/\//i.test(t) && t.split(/\s+/).length === 1) return 'url';
  if (/^[\w._%+-]+@[\w.-]+\.[a-z]{2,}$/i.test(t)) return 'email';
  if (/@[\w.-]+\.[a-z]{2,}/i.test(t) && t.length < 200) return 'email_with_text';
  return 'message';
}
