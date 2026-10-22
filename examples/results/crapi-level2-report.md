# Report di sicurezza — Gauntlet

Questo documento elenca i problemi di sicurezza rilevati sull'applicazione,
spiegati in modo semplice. Per ciascuno trovi **cosa è stato trovato**, **quanto
è grave**, **come correggerlo** e **cosa rischi se lo ignori**. I problemi sono
ordinati dal più urgente al meno urgente.

## Dati dell'esecuzione

- **Bersaglio analizzato (target):** http://host.docker.internal:30080
- **Livello di conoscenza:** 2
- **Modalità aggressiva:** no
- **Data e ora:** 2026-10-22 10:32

> ⚠️ **Attenzione — dati sensibili.** Le sezioni "Prova concreta" di questo report possono contenere estratti delle risposte (dati reali, PII, token di sessione) catturati dai controlli: trattalo come un documento riservato, non condividerlo né archiviarlo in chiaro senza averlo prima rivisto e oscurato.

## Riepilogo

Totale problemi rilevati: **20**.

- CRITICA: 3
- ALTA: 0
- MEDIA: 3
- BASSA: 13
- INFO: 1

## Problemi rilevati (dal più urgente)

### 1. Accesso cross-tenant confermato (IDOR/BOLA)

**Gravità:** CRITICA — da correggere subito: può causare un danno grave e concreto.

**Che cosa è stato trovato:** Il tenant 'cliente_b' ha letto la risorsa http://host.docker.internal:30080/identity/api/v2/vehicle/41b16f7d-9020-4090-bb51-2b6b590873ac/location, di proprietà del tenant 'cliente_a': risposta 200 contenente il marcatore del seed 'gauntlet-a@example.com'. L'isolamento tra clienti è violato.

**Dove:** http://host.docker.internal:30080/identity/api/v2/vehicle/41b16f7d-9020-4090-bb51-2b6b590873ac/location

**Prova concreta:**

```
GET http://host.docker.internal:30080/identity/api/v2/vehicle/41b16f7d-9020-4090-bb51-2b6b590873ac/location come 'cliente_b' -> 200; marcatore 'gauntlet-a@example.com' presente nel corpo (estratto: '{"carId":"41b16f7d-9020-4090-bb51-2b6b590873ac","vehicleLocation":{"id":5,"latitude":"37.406769","longitude":"-94.705528"},"fullName":"Gauntlet A","email":"gauntlet-a@example.com"}').
```

**Come correggere:** Imporre l'autorizzazione per oggetto lato server: ogni accesso a una risorsa deve verificare che appartenga al tenant della sessione, non fidarsi dell'ID in ingresso.

**Se ignori il problema:** Un cliente può leggere (e potenzialmente modificare) i dati di un altro cliente: violazione di riservatezza e, se applicabile, del GDPR.

_Origine del controllo: test di controllo degli accessi · confidenza del rilevamento: 100%._

### 2. Accesso cross-tenant confermato (IDOR/BOLA)

**Gravità:** CRITICA — da correggere subito: può causare un danno grave e concreto.

**Che cosa è stato trovato:** Il tenant 'cliente_a' ha letto la risorsa http://host.docker.internal:30080/identity/api/v2/vehicle/419c8b18-ef49-4216-88c9-5acf530addcf/location, di proprietà del tenant 'cliente_b': risposta 200 contenente il marcatore del seed 'gauntlet-b@example.com'. L'isolamento tra clienti è violato.

**Dove:** http://host.docker.internal:30080/identity/api/v2/vehicle/419c8b18-ef49-4216-88c9-5acf530addcf/location

**Prova concreta:**

```
GET http://host.docker.internal:30080/identity/api/v2/vehicle/419c8b18-ef49-4216-88c9-5acf530addcf/location come 'cliente_a' -> 200; marcatore 'gauntlet-b@example.com' presente nel corpo (estratto: '{"carId":"419c8b18-ef49-4216-88c9-5acf530addcf","vehicleLocation":{"id":5,"latitude":"37.406769","longitude":"-94.705528"},"fullName":"Gauntlet B","email":"gauntlet-b@example.com"}').
```

**Come correggere:** Imporre l'autorizzazione per oggetto lato server: ogni accesso a una risorsa deve verificare che appartenga al tenant della sessione, non fidarsi dell'ID in ingresso.

**Se ignori il problema:** Un cliente può leggere (e potenzialmente modificare) i dati di un altro cliente: violazione di riservatezza e, se applicabile, del GDPR.

_Origine del controllo: test di controllo degli accessi · confidenza del rilevamento: 100%._

### 3. JWT alg=none accettato

**Gravità:** CRITICA — da correggere subito: può causare un danno grave e concreto.

**Che cosa è stato trovato:** Il server ha accettato un token JWT forgiato con header 'alg: none' e firma vuota (stessa payload del token reale): la GET su http://host.docker.internal:30080/identity/api/v2/vehicle/41b16f7d-9020-4090-bb51-2b6b590873ac/location ha risposto 200 con il contenuto protetto atteso. La firma del token non viene verificata: chiunque può fabbricare un token valido con qualsiasi identità e privilegio.

**Dove:** http://host.docker.internal:30080/identity/api/v2/vehicle/41b16f7d-9020-4090-bb51-2b6b590873ac/location

**Prova concreta:**

```
GET http://host.docker.internal:30080/identity/api/v2/vehicle/41b16f7d-9020-4090-bb51-2b6b590873ac/location con un token 'alg: none' a firma vuota -> 200; il marcatore della risorsa protetta 'gauntlet-a@example.com' è presente nel corpo (token non firmato accettato).
```

**Come correggere:** Rifiutare esplicitamente i token con 'alg: none' lato server e fissare l'algoritmo atteso (allowlist di algoritmi); non dedurre mai l'algoritmo di verifica dall'header del token.

**Se ignori il problema:** Un attaccante può forgiare un token per qualsiasi utente (compreso un amministratore) e autenticarsi come chiunque: compromissione totale dell'autenticazione.

_Origine del controllo: controllo delle debolezze JWT · confidenza del rilevamento: 100%._

### 4. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:30080/sitemap.xml

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 5. Missing Anti-clickjacking Header

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** The response does not protect against 'ClickJacking' attacks. It should include either Content-Security-Policy with 'frame-ancestors' directive or X-Frame-Options.

**Dove:** http://host.docker.internal:30080

**Come correggere:** Modern Web browsers support the Content-Security-Policy and X-Frame-Options HTTP headers. Ensure one of them is set on all web pages returned by your site/app.
If you expect the page to be framed only by pages on your server (e.g. it's part of a FRAMESET) then you'll want to use SAMEORIGIN, otherwise if you never expect the page to be framed, you should use DENY. Alternatively consider implementing Content Security Policy's "frame-ancestors" directive.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 6. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:30080

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 7. Server Leaks Version Information via "Server" HTTP Response Header Field

**Gravità:** BASSA — miglioria consigliata: rischio limitato.

**Che cosa è stato trovato:** The web/application server is leaking version information via the "Server" HTTP response header. Access to such information may facilitate attackers identifying other vulnerabilities your web/application server is subject to.

**Dove:** http://host.docker.internal:30080/images/logo192.png

**Prova concreta:**

```
openresty/1.27.1.2
```

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to suppress the "Server" header or provide generic details.

**Se ignori il problema:** Impatto limitato; da correggere nella normale manutenzione.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 8. Server Leaks Version Information via "Server" HTTP Response Header Field

**Gravità:** BASSA — miglioria consigliata: rischio limitato.

**Che cosa è stato trovato:** The web/application server is leaking version information via the "Server" HTTP response header. Access to such information may facilitate attackers identifying other vulnerabilities your web/application server is subject to.

**Dove:** http://host.docker.internal:30080/robots.txt

**Prova concreta:**

```
openresty/1.27.1.2
```

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to suppress the "Server" header or provide generic details.

**Se ignori il problema:** Impatto limitato; da correggere nella normale manutenzione.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 9. X-Content-Type-Options Header Missing

**Gravità:** BASSA — miglioria consigliata: rischio limitato.

**Che cosa è stato trovato:** The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'. This allows older versions of Internet Explorer and Chrome to perform MIME-sniffing on the response body, potentially causing the response body to be interpreted and displayed as a content type other than the declared content type. Current (early 2014) and legacy versions of Firefox will use the declared content type (if one is set), rather than performing MIME-sniffing.

**Dove:** http://host.docker.internal:30080/images/logo192.png

**Come correggere:** Ensure that the application/web server sets the Content-Type header appropriately, and that it sets the X-Content-Type-Options header to 'nosniff' for all web pages.
If possible, ensure that the end user uses a standards-compliant and modern web browser that does not perform MIME-sniffing at all, or that can be directed by the web application/web server to not perform MIME-sniffing.

**Se ignori il problema:** Impatto limitato; da correggere nella normale manutenzione.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 10. X-Content-Type-Options Header Missing

**Gravità:** BASSA — miglioria consigliata: rischio limitato.

**Che cosa è stato trovato:** The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'. This allows older versions of Internet Explorer and Chrome to perform MIME-sniffing on the response body, potentially causing the response body to be interpreted and displayed as a content type other than the declared content type. Current (early 2014) and legacy versions of Firefox will use the declared content type (if one is set), rather than performing MIME-sniffing.

**Dove:** http://host.docker.internal:30080/robots.txt

**Come correggere:** Ensure that the application/web server sets the Content-Type header appropriately, and that it sets the X-Content-Type-Options header to 'nosniff' for all web pages.
If possible, ensure that the end user uses a standards-compliant and modern web browser that does not perform MIME-sniffing at all, or that can be directed by the web application/web server to not perform MIME-sniffing.

**Se ignori il problema:** Impatto limitato; da correggere nella normale manutenzione.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 11. Server Leaks Version Information via "Server" HTTP Response Header Field

**Gravità:** BASSA — miglioria consigliata: rischio limitato.

**Che cosa è stato trovato:** The web/application server is leaking version information via the "Server" HTTP response header. Access to such information may facilitate attackers identifying other vulnerabilities your web/application server is subject to.

**Dove:** http://host.docker.internal:30080/sitemap.xml

**Prova concreta:**

```
openresty/1.27.1.2
```

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to suppress the "Server" header or provide generic details.

**Se ignori il problema:** Impatto limitato; da correggere nella normale manutenzione.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 12. Server Leaks Version Information via "Server" HTTP Response Header Field

**Gravità:** BASSA — miglioria consigliata: rischio limitato.

**Che cosa è stato trovato:** The web/application server is leaking version information via the "Server" HTTP response header. Access to such information may facilitate attackers identifying other vulnerabilities your web/application server is subject to.

**Dove:** http://host.docker.internal:30080

**Prova concreta:**

```
openresty/1.27.1.2
```

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to suppress the "Server" header or provide generic details.

**Se ignori il problema:** Impatto limitato; da correggere nella normale manutenzione.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 13. X-Content-Type-Options Header Missing

**Gravità:** BASSA — miglioria consigliata: rischio limitato.

**Che cosa è stato trovato:** The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'. This allows older versions of Internet Explorer and Chrome to perform MIME-sniffing on the response body, potentially causing the response body to be interpreted and displayed as a content type other than the declared content type. Current (early 2014) and legacy versions of Firefox will use the declared content type (if one is set), rather than performing MIME-sniffing.

**Dove:** http://host.docker.internal:30080

**Come correggere:** Ensure that the application/web server sets the Content-Type header appropriately, and that it sets the X-Content-Type-Options header to 'nosniff' for all web pages.
If possible, ensure that the end user uses a standards-compliant and modern web browser that does not perform MIME-sniffing at all, or that can be directed by the web application/web server to not perform MIME-sniffing.

**Se ignori il problema:** Impatto limitato; da correggere nella normale manutenzione.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 14. Server Leaks Version Information via "Server" HTTP Response Header Field

**Gravità:** BASSA — miglioria consigliata: rischio limitato.

**Che cosa è stato trovato:** The web/application server is leaking version information via the "Server" HTTP response header. Access to such information may facilitate attackers identifying other vulnerabilities your web/application server is subject to.

**Dove:** http://host.docker.internal:30080/images/favicon.ico

**Prova concreta:**

```
openresty/1.27.1.2
```

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to suppress the "Server" header or provide generic details.

**Se ignori il problema:** Impatto limitato; da correggere nella normale manutenzione.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 15. X-Content-Type-Options Header Missing

**Gravità:** BASSA — miglioria consigliata: rischio limitato.

**Che cosa è stato trovato:** The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'. This allows older versions of Internet Explorer and Chrome to perform MIME-sniffing on the response body, potentially causing the response body to be interpreted and displayed as a content type other than the declared content type. Current (early 2014) and legacy versions of Firefox will use the declared content type (if one is set), rather than performing MIME-sniffing.

**Dove:** http://host.docker.internal:30080/images/favicon.ico

**Come correggere:** Ensure that the application/web server sets the Content-Type header appropriately, and that it sets the X-Content-Type-Options header to 'nosniff' for all web pages.
If possible, ensure that the end user uses a standards-compliant and modern web browser that does not perform MIME-sniffing at all, or that can be directed by the web application/web server to not perform MIME-sniffing.

**Se ignori il problema:** Impatto limitato; da correggere nella normale manutenzione.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 16. Server Leaks Version Information via "Server" HTTP Response Header Field

**Gravità:** BASSA — miglioria consigliata: rischio limitato.

**Che cosa è stato trovato:** The web/application server is leaking version information via the "Server" HTTP response header. Access to such information may facilitate attackers identifying other vulnerabilities your web/application server is subject to.

**Dove:** http://host.docker.internal:30080/manifest.json

**Prova concreta:**

```
openresty/1.27.1.2
```

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to suppress the "Server" header or provide generic details.

**Se ignori il problema:** Impatto limitato; da correggere nella normale manutenzione.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 17. X-Content-Type-Options Header Missing

**Gravità:** BASSA — miglioria consigliata: rischio limitato.

**Che cosa è stato trovato:** The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'. This allows older versions of Internet Explorer and Chrome to perform MIME-sniffing on the response body, potentially causing the response body to be interpreted and displayed as a content type other than the declared content type. Current (early 2014) and legacy versions of Firefox will use the declared content type (if one is set), rather than performing MIME-sniffing.

**Dove:** http://host.docker.internal:30080/manifest.json

**Come correggere:** Ensure that the application/web server sets the Content-Type header appropriately, and that it sets the X-Content-Type-Options header to 'nosniff' for all web pages.
If possible, ensure that the end user uses a standards-compliant and modern web browser that does not perform MIME-sniffing at all, or that can be directed by the web application/web server to not perform MIME-sniffing.

**Se ignori il problema:** Impatto limitato; da correggere nella normale manutenzione.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 18. Server Leaks Version Information via "Server" HTTP Response Header Field

**Gravità:** BASSA — miglioria consigliata: rischio limitato.

**Che cosa è stato trovato:** The web/application server is leaking version information via the "Server" HTTP response header. Access to such information may facilitate attackers identifying other vulnerabilities your web/application server is subject to.

**Dove:** http://host.docker.internal:30080/static/css/main.dd33429d.css

**Prova concreta:**

```
openresty/1.27.1.2
```

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to suppress the "Server" header or provide generic details.

**Se ignori il problema:** Impatto limitato; da correggere nella normale manutenzione.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 19. X-Content-Type-Options Header Missing

**Gravità:** BASSA — miglioria consigliata: rischio limitato.

**Che cosa è stato trovato:** The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'. This allows older versions of Internet Explorer and Chrome to perform MIME-sniffing on the response body, potentially causing the response body to be interpreted and displayed as a content type other than the declared content type. Current (early 2014) and legacy versions of Firefox will use the declared content type (if one is set), rather than performing MIME-sniffing.

**Dove:** http://host.docker.internal:30080/static/css/main.dd33429d.css

**Come correggere:** Ensure that the application/web server sets the Content-Type header appropriately, and that it sets the X-Content-Type-Options header to 'nosniff' for all web pages.
If possible, ensure that the end user uses a standards-compliant and modern web browser that does not perform MIME-sniffing at all, or that can be directed by the web application/web server to not perform MIME-sniffing.

**Se ignori il problema:** Impatto limitato; da correggere nella normale manutenzione.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 20. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:30080

**Prova concreta:**

```
<script defer="defer" src="/static/js/main.8c78208c.js"></script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._
