# Report di sicurezza — Gauntlet

Questo documento elenca i problemi di sicurezza rilevati sull'applicazione,
spiegati in modo semplice. Per ciascuno trovi **cosa è stato trovato**, **quanto
è grave**, **come correggerlo** e **cosa rischi se lo ignori**. I problemi sono
ordinati dal più urgente al meno urgente.

## Dati dell'esecuzione

- **Bersaglio analizzato (target):** http://host.docker.internal:3000
- **Livello di conoscenza:** 1
- **Modalità aggressiva:** no
- **Data e ora:** 2026-10-22 10:37

> ⚠️ **Attenzione — dati sensibili.** Le sezioni "Prova concreta" di questo report possono contenere estratti delle risposte (dati reali, PII, token di sessione) catturati dai controlli: trattalo come un documento riservato, non condividerlo né archiviarlo in chiaro senza averlo prima rivisto e oscurato.

## Riepilogo

Totale problemi rilevati: **236**.

- CRITICA: 0
- ALTA: 0
- MEDIA: 169
- BASSA: 0
- INFO: 67

## Problemi rilevati (dal più urgente)

### 1. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/robots.txt

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 2. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/sitemap.xml

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 3. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 4. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/sitemap.xml

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 5. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 6. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/assets/public/favicon_js.ico

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 7. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/styles.css

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 8. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/rolldown-runtime-BoHGiXSq.js

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 9. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/polyfills.js

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 10. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/chunk-DBPdFzgj.js

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 11. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/scripts.js

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 12. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/chunk-1qQQGal7.js

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 13. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/chunk-Cv2YgWUq.js

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 14. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/main.js

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 15. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/ftp/eastere.gg

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 16. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/ftp/coupons_2013.md.bak

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 17. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/ftp/coupons_2013.md.bak

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 18. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/ftp/eastere.gg

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 19. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/ftp/encrypt.pyc

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 20. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/ftp

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 21. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/ftp

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 22. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/ftp/encrypt.pyc

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 23. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/ftp/package-lock.json.bak

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 24. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/ftp/incident-support.kdbx

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 25. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/ftp/package-lock.json.bak

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 26. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/ftp/acquisitions.md

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 27. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 28. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 29. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/ftp/suspicious_errors.yml

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 30. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/ftp/suspicious_errors.yml

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 31. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/ftp/legal.md

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 32. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/ftp/package.json.bak

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 33. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/ftp/package.json.bak

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 34. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/fileServer.js:68:18

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 35. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/fileServer.js:52:13

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 36. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/fileServer.js:68:18

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 37. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/fileServer.js:52:13

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 38. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/ftp/announcement_encrypted.md

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 39. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/layer.js:95:5

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 40. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/layer.js:95:5

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 41. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/index.js:328:13

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 42. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/index.js:328:13

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 43. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/index.js:365:14

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 44. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/index.js:365:14

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 45. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/index.js:286:9

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 46. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/index.js:286:9

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 47. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/index.js:376:14

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 48. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/index.js:376:14

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 49. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/index.js:280:10

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 50. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/index.js:280:10

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 51. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/assets/public/favicon_js.ico

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 52. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/assets/public/favicon_js.ico

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 53. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/styles.css

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 54. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/styles.css

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 55. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/rolldown-runtime-BoHGiXSq.js

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 56. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/rolldown-runtime-BoHGiXSq.js

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 57. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/index.js:149:39

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 58. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/index.js:149:39

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 59. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/chunk-1qQQGal7.js

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 60. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/chunk-1qQQGal7.js

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 61. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/chunk-DBPdFzgj.js

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 62. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/chunk-DBPdFzgj.js

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 63. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/index.js:421:3

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 64. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/index.js:421:3

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 65. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/polyfills.js

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 66. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/polyfills.js

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 67. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/assets/public/favicon_js.ico

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 68. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/assets/public/favicon_js.ico

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 69. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/main.js

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 70. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/main.js

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 71. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/scripts.js

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 72. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/scripts.js

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 73. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/styles.css

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 74. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/styles.css

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 75. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/chunk-Cv2YgWUq.js

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 76. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/chunk-Cv2YgWUq.js

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 77. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/rolldown-runtime-BoHGiXSq.js

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 78. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/rolldown-runtime-BoHGiXSq.js

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 79. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/polyfills.js

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 80. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/polyfills.js

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 81. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/chunk-DBPdFzgj.js

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 82. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/chunk-DBPdFzgj.js

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 83. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/chunk-Cv2YgWUq.js

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 84. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/chunk-Cv2YgWUq.js

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 85. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/chunk-1qQQGal7.js

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 86. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/chunk-1qQQGal7.js

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 87. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/assets/public/assets/public/favicon_js.ico

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 88. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/assets/public/assets/public/favicon_js.ico

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 89. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/scripts.js

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 90. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/scripts.js

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 91. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/assets/public/styles.css

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 92. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/main.js

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 93. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/main.js

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 94. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/assets/public/styles.css

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 95. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/assets/public/chunk-Cv2YgWUq.js

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 96. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/assets/public/chunk-Cv2YgWUq.js

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 97. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/assets/public/rolldown-runtime-BoHGiXSq.js

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 98. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/assets/public/rolldown-runtime-BoHGiXSq.js

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 99. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/assets/public/favicon_js.ico

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 100. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/assets/public/favicon_js.ico

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 101. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/assets/public/chunk-DBPdFzgj.js

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 102. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/assets/public/chunk-DBPdFzgj.js

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 103. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/chunk-DBPdFzgj.js

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 104. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/chunk-DBPdFzgj.js

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 105. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/styles.css

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 106. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/styles.css

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 107. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/rolldown-runtime-BoHGiXSq.js

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 108. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/rolldown-runtime-BoHGiXSq.js

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 109. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/chunk-1qQQGal7.js

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 110. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/chunk-1qQQGal7.js

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 111. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/polyfills.js

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 112. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/polyfills.js

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 113. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/chunk-Cv2YgWUq.js

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 114. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/chunk-Cv2YgWUq.js

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 115. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/scripts.js

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 116. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/scripts.js

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 117. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/assets/public/polyfills.js

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 118. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/assets/public/polyfills.js

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 119. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/assets/public/scripts.js

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 120. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/assets/public/scripts.js

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 121. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/assets/public/chunk-1qQQGal7.js

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 122. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/assets/public/chunk-1qQQGal7.js

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 123. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/main.js

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 124. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/main.js

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 125. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/assets/public/main.js

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 126. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/assets/public/main.js

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 127. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/assets/public/styles.css

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 128. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/assets/public/styles.css

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 129. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/assets/public/chunk-DBPdFzgj.js

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 130. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/assets/public/chunk-DBPdFzgj.js

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 131. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/assets/public/rolldown-runtime-BoHGiXSq.js

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 132. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/assets/public/rolldown-runtime-BoHGiXSq.js

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 133. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/assets/public/chunk-Cv2YgWUq.js

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 134. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/assets/public/chunk-Cv2YgWUq.js

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 135. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/assets/public/assets/public/favicon_js.ico

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 136. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/assets/public/assets/public/favicon_js.ico

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 137. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/assets/public/chunk-1qQQGal7.js

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 138. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/assets/public/chunk-1qQQGal7.js

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 139. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/assets/public/polyfills.js

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 140. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/assets/public/polyfills.js

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 141. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/assets/public/scripts.js

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 142. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/assets/public/scripts.js

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 143. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/assets/public/main.js

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 144. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/assets/public/main.js

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 145. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/assets/public/assets/public/favicon_js.ico

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 146. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/assets/public/assets/public/favicon_js.ico

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 147. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/assets/public/chunk-Cv2YgWUq.js

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 148. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/assets/public/chunk-Cv2YgWUq.js

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 149. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/assets/public/rolldown-runtime-BoHGiXSq.js

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 150. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/assets/public/rolldown-runtime-BoHGiXSq.js

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 151. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/assets/public/styles.css

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 152. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/assets/public/styles.css

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 153. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/assets/public/chunk-DBPdFzgj.js

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 154. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/assets/public/chunk-DBPdFzgj.js

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 155. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/assets/public/chunk-1qQQGal7.js

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 156. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/assets/public/chunk-1qQQGal7.js

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 157. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/assets/public/polyfills.js

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 158. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/assets/public/polyfills.js

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 159. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/assets/public/scripts.js

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 160. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/assets/public/scripts.js

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 161. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/assets/public/main.js

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 162. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/assets/public/main.js

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 163. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/ftp/quarantine/juicy_malware_macos_64.url

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 164. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/ftp/quarantine/juicy_malware_linux_amd_64.url

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 165. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/ftp/quarantine/juicy_malware_windows_64.exe.url

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 166. Content Security Policy (CSP) Header Not Set

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

**Dove:** http://host.docker.internal:3000/ftp/quarantine

**Come correggere:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 75%._

### 167. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/ftp/quarantine/juicy_malware_linux_arm_64.url

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 168. Cross-Domain Misconfiguration

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

**Dove:** http://host.docker.internal:3000/ftp/quarantine

**Prova concreta:**

```
Access-Control-Allow-Origin: *
```

**Come correggere:** Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

**Se ignori il problema:** Possibile abuso in combinazione con altri difetti o accessi.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 169. CORS: allow-origin con wildcard permissivo

**Gravità:** MEDIA — da sistemare: non è un'emergenza, ma non va trascurato.

**Che cosa è stato trovato:** L'endpoint http://host.docker.internal:3000 ha restituito 'Access-Control-Allow-Origin: *', consentendo a qualsiasi origine di leggerne le risposte via browser. Con il wildcard i browser ignorano 'Allow-Credentials: true', quindi le richieste con credenziali non sono esposte, ma i dati non autenticati sì.

**Dove:** http://host.docker.internal:3000

**Prova concreta:**

```
GET http://host.docker.internal:3000 con 'Origin: https://gauntlet-cors-probe.example' -> Access-Control-Allow-Origin: * (wildcard).
```

**Come correggere:** Restringere 'Access-Control-Allow-Origin' a un'allowlist di origini fidate invece del wildcard, soprattutto su endpoint che espongono dati non pubblici.

**Se ignori il problema:** Qualsiasi sito può leggere via browser le risposte non autenticate di questo endpoint.

_Origine del controllo: controllo della configurazione CORS · confidenza del rilevamento: 100%._

### 170. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 171. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/sitemap.xml

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 172. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 173. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/fileServer.js:68:18

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 174. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/fileServer.js:52:13

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 175. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/layer.js:95:5

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 176. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/index.js:328:13

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 177. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/index.js:365:14

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 178. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/index.js:286:9

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 179. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/index.js:376:14

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 180. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/index.js:280:10

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 181. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/assets/public/favicon_js.ico

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 182. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/styles.css

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 183. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/index.js:149:39

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 184. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/index.js:421:3

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 185. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/chunk-1qQQGal7.js

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 186. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/rolldown-runtime-BoHGiXSq.js

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 187. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/assets/public/favicon_js.ico

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 188. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/chunk-DBPdFzgj.js

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 189. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/styles.css

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 190. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/polyfills.js

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 191. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/main.js

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 192. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/chunk-Cv2YgWUq.js

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 193. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/scripts.js

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 194. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/rolldown-runtime-BoHGiXSq.js

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 195. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/polyfills.js

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 196. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/assets/public/assets/public/favicon_js.ico

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 197. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/chunk-DBPdFzgj.js

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 198. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/chunk-Cv2YgWUq.js

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 199. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/chunk-1qQQGal7.js

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 200. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/assets/public/styles.css

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 201. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/scripts.js

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 202. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/assets/public/favicon_js.ico

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 203. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/assets/public/chunk-Cv2YgWUq.js

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 204. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/main.js

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 205. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/assets/public/rolldown-runtime-BoHGiXSq.js

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 206. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/styles.css

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 207. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/assets/public/chunk-DBPdFzgj.js

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 208. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/chunk-DBPdFzgj.js

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 209. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/chunk-1qQQGal7.js

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 210. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/rolldown-runtime-BoHGiXSq.js

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 211. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/polyfills.js

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 212. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/scripts.js

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 213. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/chunk-Cv2YgWUq.js

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 214. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/assets/public/polyfills.js

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 215. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/main.js

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 216. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/assets/public/scripts.js

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 217. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/assets/public/chunk-1qQQGal7.js

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 218. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/assets/public/styles.css

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 219. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/build/routes/assets/public/main.js

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 220. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/assets/public/assets/public/favicon_js.ico

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 221. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/assets/public/rolldown-runtime-BoHGiXSq.js

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 222. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/assets/public/chunk-DBPdFzgj.js

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 223. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/assets/public/chunk-Cv2YgWUq.js

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 224. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/assets/public/chunk-1qQQGal7.js

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 225. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/assets/public/polyfills.js

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 226. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/assets/public/assets/public/favicon_js.ico

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 227. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/assets/public/main.js

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 228. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/express/lib/router/assets/public/scripts.js

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 229. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/assets/public/styles.css

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 230. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/assets/public/chunk-Cv2YgWUq.js

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 231. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/assets/public/chunk-1qQQGal7.js

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 232. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/assets/public/rolldown-runtime-BoHGiXSq.js

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 233. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/assets/public/chunk-DBPdFzgj.js

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 234. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/assets/public/polyfills.js

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 235. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/assets/public/scripts.js

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._

### 236. Modern Web Application

**Gravità:** INFO — solo informativo: nessuna azione urgente richiesta.

**Che cosa è stato trovato:** The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

**Dove:** http://host.docker.internal:3000/juice-shop/node_modules/serve-index/assets/public/main.js

**Prova concreta:**

```
<script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
          "popup": { "background": "var(--theme-primary)", "text": "var(--theme-text)" },
          "button": { "background": "var(--theme-accent)", "text": "var(--theme-text)" }
        },
        "theme": "classic",
        "position": "bottom-right",
        "content": { "message": "This website uses fruit cookies to ensure you get the juiciest tracking experience.", "dismiss": "Me want it!", "link": "But me wait!", "href": "https://www.youtube.com/watch?v=9PnbKL3wuH4" }
      })});
  </script>
```

**Come correggere:** This is an informational alert and so no changes are required.

**Se ignori il problema:** Informativo: nessun impatto diretto, utile per l'hardening.

_Origine del controllo: scansione automatica (ZAP) · confidenza del rilevamento: 50%._
