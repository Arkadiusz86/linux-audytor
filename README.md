# 🔐 SSH Security Auditor

> Webowa aplikacja w stylu Kali Linux do zdalnego audytu bezpieczeństwa firewalla przez SSH.

![Zrzut ekranu](11.png)

---

## ✨ Co robi ta aplikacja?

SSH Security Auditor łączy się przez SSH z podanym hostem i wykonuje automatyczny audyt reguł firewalla. Całość działa przez przeglądarkę — wystarczy podać dane SSH, a aplikacja zwraca raport bezpieczeństwa w czytelnym formacie.

**Funkcje:**
- Połączenie SSH z dowolnym hostem (IP/domena, port, login, hasło lub klucz)
- Audyt reguł `iptables` / `nftables` / `ufw`
- Ocena bezpieczeństwa z opisem znalezionych problemów
- Interfejs w stylu terminala Kali Linux
- Wbudowany serwer HTTPS (self-signed cert)
- Rate limiting (5 audytów/min per IP) i ochrona CORS

---

## 🚀 Uruchomienie u siebie

### Wymagania

- **Node.js** >= 14.0.0 ([pobierz](https://nodejs.org/))
- Dostęp SSH do hosta, który chcesz audytować

### Instalacja

```bash
# 1. Sklonuj repozytorium
git clone https://github.com/TWOJ_USERNAME/ssh-security-auditor.git
cd ssh-security-auditor

# 2. Zainstaluj zależności
npm install

# 3. Skonfiguruj zmienne środowiskowe
cp .env.example .env
```

### Konfiguracja `.env`

Otwórz plik `.env` i uzupełnij wartości:

```env
# Silny losowy token do autoryzacji API (min. 32 znaki)
# Generuj komendą: node -e "const c=require('crypto');console.log(c.randomBytes(32).toString('hex'))"
AUDIT_API_TOKEN=tu-wkej-swoj-wygenerowany-token

# Środowisko (production / development)
NODE_ENV=production

# Port HTTPS
PORT=8443

# Dozwolony origin CORS (adres, z którego będziesz korzystać z aplikacji)
ALLOWED_ORIGIN=https://localhost:8443
```

### Generowanie certyfikatu SSL

Aplikacja wymaga certyfikatu SSL. Wygeneruj self-signed cert:

```bash
mkdir certs
openssl req -x509 -newkey rsa:4096 -keyout certs/key.pem -out certs/cert.pem \
  -days 365 -nodes -subj "/CN=localhost"
```

### Uruchomienie

```bash
# Produkcja
npm start

# Tryb deweloperski (auto-restart)
npm run dev
```

Aplikacja będzie dostępna pod adresem: **https://localhost:8443**

> ⚠️ Przeglądarka wyświetli ostrzeżenie o self-signed certyfikacie — to normalne. Kliknij „Zaawansowane → Przejdź mimo to".

---

## 🔒 Bezpieczeństwo

- Nigdy nie commituj pliku `.env` do repozytorium (jest w `.gitignore`)
- Token API powinien mieć minimum 32 losowe znaki
- Aplikacja powinna działać w sieci lokalnej lub za VPN, nie wystawiaj jej bezpośrednio na internet

---

## 🛠 Stack technologiczny

| Technologia | Zastosowanie |
|---|---|
| Node.js + Express | Backend, serwer HTTPS |
| ssh2 | Połączenia SSH |
| helmet | Nagłówki bezpieczeństwa HTTP |
| express-rate-limit | Ochrona przed nadużyciami |
| Vanilla JS | Frontend |

---

## 📄 Licencja

MIT — używaj swobodnie.
# linux-audytor
# linux-audytor
