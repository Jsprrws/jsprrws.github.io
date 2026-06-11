---
title: "ffuf Avanzado — Arsenal Completo de Fuzzing Web"
date: 2026-06-10 15:00:00 -0600
categories: [Seguridad Ofensiva, Fuzzing]
tags: [ffuf, fuzzing, bug-bounty, directorios, parametros, archivos, api, vhost, waf-bypass, sesiones, autenticado, recon]
pin: true
math: false
mermaid: true
toc: true
comments: true
---

> `ffuf` no escanea — **inyecta** tu wordlist exactamente donde pongas el keyword `FUZZ`. Todo lo demás (la URL, los headers, el cuerpo, el método) es contexto que tú controlas. El profesional no memoriza comandos: decide *qué busca*, pone el `FUZZ` ahí, elige el modo de ataque correcto y filtra todo lo que no sea señal. Esta página es ese flujo de decisión, por caso de uso.
{: .prompt-info }

## El Árbol de Decisión del Operador

```mermaid
flowchart TD
    A[¿Qué busco?] --> B[Rutas / archivos]
    A --> C[Parámetros ocultos]
    A --> D[Valores: IDOR / IDs]
    A --> E[Vhosts internos]
    A --> F[Endpoints de API]
    B --> G{¿Una posición<br/>o varias?}
    G -->|Una| H[Default / sniper]
    G -->|Varias| I[clusterbomb / pitchfork]
    C --> J[FUZZ en nombre<br/>de parámetro]
    D --> K[FUZZ en valor +<br/>filtrar por tamaño]
    E --> L[FUZZ en header Host]
    F --> M[FUZZ en path JSON +<br/>sesión autenticada]
    style A fill:#1f6feb,color:#fff
```

> **Disciplina de alcance:** todo fuzzing toca al objetivo y genera tráfico visible. Ejecútalo solo contra activos que poseas o estés autorizado por escrito a probar. En bug bounty, fuzzear fuera del scope definido puede sacarte del programa o constituir un delito.
{: .prompt-danger }

---

## 1. Fundamentos — Dónde va el `FUZZ`

El concepto que lo gobierna todo: el keyword puede ir en cualquier parte de la petición.

| Posición | Sintaxis | Caso de uso |
|----------|----------|-------------|
| Ruta / archivo | `-u https://t.com/FUZZ` | Descubrir directorios y archivos |
| VHost | `-H "Host: FUZZ.t.com"` | Virtual hosts sin DNS |
| Nombre de parámetro | `-d "FUZZ=test"` | Parámetros ocultos |
| Valor de parámetro | `-d "id=FUZZ"` | IDOR, inyección, enumeración |
| Header | `-H "X-API-Key: FUZZ"` | Valores de headers |
| Dentro de JSON | `-d '{"id":"FUZZ"}'` | APIs REST |
| Cualquier keyword | `-w lista.txt:KEYWORD` | Múltiples posiciones |

---

## Referencia Rápida — Una Opción, Un Ejemplo

Tabla de arranque: cada flag clave con un comando de ejemplo listo para copiar.

| Comando de ejemplo | Qué hace |
|--------------------|----------|
| `ffuf -u https://target.com/FUZZ -w wordlist.txt -rate 50` | **`-rate 50`** — limita a 50 req/s para no ser bloqueado por el WAF. |
| `ffuf -u https://target.com/FUZZ -w wordlist.txt -p 0.1` | **`-p 0.1`** — *delay* de 0.1 s entre cada petición (sigilo / anti rate-limit). |
| `ffuf -u https://target.com/FUZZ -w wordlist.txt -e .php,.asp,.aspx,.jsp,.bak,.old,.txt` | **`-e`** — prueba cada palabra con esas extensiones para ver si existen variantes. |
| `ffuf -u https://target.com/FUZZ -w wordlist.txt -mc 200,301,302,403` | **`-mc`** — muestra solo esos códigos de respuesta exactos. |
| `ffuf -u https://target.com/api/FUZZ -w endpoints.txt:FUZZ -w ids.txt:PARAM -X POST -d '{"id":"PARAM"}' -H "Cookie: auth=eyJhbGci..." -H "Content-Type: application/json" -mode pitchfork` | **`-d` + `-H` + pitchfork** — fuzzea endpoint e ID a la vez; `-d` inyecta el parámetro en el cuerpo, `-H` pasa la cookie de auth. |
| `ffuf -u https://target.com/api/data -X POST -d "FUZZ=test" -w burp-parameter-names.txt -b "session=TU_COOKIE" -H "Content-Type: application/x-www-form-urlencoded" -fc 401,403` | **`-b` + `-d`** — `-b` pasa la cookie de sesión, `-d` el parámetro POST; `-fc` excluye 401/403. |
| `ffuf -u http://IP:PORT/post.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "y=FUZZ" -w common.txt -mc 200 -v` | **`-d "y=FUZZ"` + `-v`** — fuzzea el *valor* del parámetro `y`; `-v` muestra la URL completa de cada match. |

> Nota de corrección: el flag de pausa es **`-p`** (*delay*), no "relay". Y para varias wordlists la sintaxis es **`-w archivo:KEYWORD`** repetido (no existe `-w2`). Los ejemplos de arriba ya van corregidos.
{: .prompt-tip }

---

## La Decisión Más Subestimada — Elegir la Wordlist

Un target que parece "limpio" suele estarlo solo porque usaste la wordlist equivocada. El cazador profesional elige la lista según el contexto, no agarra `common.txt` para todo.

| Wordlist | Cuándo usarla |
|----------|---------------|
| `raft-*-directories.txt` / `raft-*-files.txt` | Descubrimiento general de dirs/archivos. Las RAFT vienen de datos reales, mejor señal que las clásicas. |
| `directory-list-2.3-medium.txt` | Cobertura amplia clásica (DirBuster). Buena para un primer barrido extenso. |
| `Assetnote (best-words, httparchive)` | Listas derivadas de millones de hosts reales. **Las mejores para bug bounty serio.** wordlists.assetnote.io |
| `api/api-endpoints.txt` (SecLists) | Específica para superficie de API. |
| `burp-parameter-names.txt` | Descubrimiento de parámetros. |
| `quickhits.txt` | Archivos sensibles de alto valor (config, backups, .git) — escaneo rápido y rentable. |
| `tech-specific (CMS/, Web-Content/<stack>)` | **Cuando ya hiciste fingerprint.** Listas de rutas propias de WordPress, WebLogic, Tomcat, etc. |

> Regla de oro: **fingerprint primero, wordlist después.** Si la Capa 3 te dijo "WebLogic/Java", una lista PHP es ruido. Usa rutas `.jsp/.do` y wordlists de WebLogic. La wordlist correcta es el multiplicador #1 de tus hallazgos.
{: .prompt-tip }

```bash
# Las wordlists de Assetnote suelen superar a SecLists en targets reales
wget https://wordlists-cdn.assetnote.io/data/automated/httparchive_directories_1m_2024.txt
ffuf -u https://target.com/FUZZ -w httparchive_directories_1m_2024.txt -ac
```

---

## Seeding — Fuzzear con Inteligencia, No a Ciegas

El error del principiante es lanzar una wordlist genérica. El profesional **siembra** la wordlist con rutas reales del target sacadas de recon pasivo: endpoints históricos, JS bundles, crawling. Una wordlist hecha a medida del target encuentra lo que ninguna lista genérica tiene.

```bash
# 1. Recolectar rutas reales del target de fuentes históricas + crawling
gau target.com 2>/dev/null | unfurl paths | sort -u > seed_paths.txt
katana -u https://target.com -jc -d 3 -silent | unfurl paths | sort -u >> seed_paths.txt
cat seed_paths.txt | sort -u > custom_wordlist.txt

# 2. Fuzzear con esa wordlist a medida (mucho mejor hit-rate que una genérica)
ffuf -u "https://target.com/FUZZ" -w custom_wordlist.txt -mc 200,403 -ac

# 3. Extraer "palabras" de las rutas para alimentar permutaciones
cat seed_paths.txt | tr '/' '\n' | tr '.' '\n' | sort -u > target_words.txt
```

> Esto es lo que hace un cazador de bounty real: no fuzzea `admin`, `login`, `test` como todo el mundo (y que el WAF ya conoce). Construye una wordlist con la nomenclatura *propia* del target — si sus rutas usan `/gestion/`, `/consulta/`, `/recarga/`, esas palabras y sus permutaciones revelan endpoints hermanos que ninguna SecLists contiene.
{: .prompt-info }

---

## 2. Descubrimiento de Directorios

```bash
# Base: directorios comunes
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -ac

# Recursivo — los directorios encontrados generan nuevo fuzzing automáticamente
ffuf -u https://target.com/FUZZ \
  -w raft-medium-directories.txt \
  -recursion -recursion-depth 2 \
  -mc 200,301,302,401,403 -ac

# Recursión con estrategia (greedy explora todo, default solo dirs)
ffuf -u https://target.com/FUZZ -w wordlist.txt \
  -recursion -recursion-strategy greedy -recursion-depth 3

# Forzar barra final (algunos servidores solo responden a directorios con /)
ffuf -u https://target.com/FUZZ/ -w wordlist.txt -ac
```

| Flag | Lógica del pentester |
|------|----------------------|
| `-recursion` | Cada dir encontrado se vuelve un nuevo punto de fuzzing. Profundidad 2 es lo sensato. |
| `-recursion-strategy greedy` | Recurre incluso en respuestas no-redirect. Más cobertura, más ruido. |
| `-mc 403` | **Siempre incluir 403.** Un directorio prohibido es un directorio que *existe* — candidato a bypass. |
| `-ac` | Auto-calibra contra catch-all/soft-404. Innegociable en apps modernas. |

---

## 3. Descubrimiento de Archivos

Los archivos son donde se filtra el oro: backups con código fuente, configs con credenciales, logs.

```bash
# Fuzzear nombres con múltiples extensiones jugosas
ffuf -u https://target.com/FUZZ \
  -w raft-medium-files.txt \
  -e .php,.asp,.aspx,.jsp,.do,.action,.bak,.old,.zip,.tar.gz,.sql,.config,.env,.log,.txt,.json,.xml,.swp,.~ \
  -mc 200,403 -ac

# Archivos de respaldo del index conocido (mutación de nombre real)
ffuf -u https://target.com/index.phpFUZZ \
  -w extensions-backup.txt   # .bak .old .swp .save ~

# Source code disclosure — extensiones que rompen el render
ffuf -u https://target.com/FUZZ \
  -w files.txt -e .phps,.php~,.php.bak,.inc,.tpl

# Archivos sensibles conocidos (config / secretos)
ffuf -u https://target.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -mc 200 -mr "DB_PASSWORD|api_key|secret|BEGIN RSA"   # match por contenido
```

> Las extensiones de backup (`.bak`, `.old`, `.swp`, `~`, `.save`) sobre archivos *que ya sabes que existen* son de los hallazgos más rentables: un `config.php.bak` se sirve como texto plano y te entrega las credenciales de la BD. Toma cada archivo confirmado y múltale la extensión.
{: .prompt-tip }

### Source disclosure — repositorios y metadatos expuestos

De los hallazgos más rentables y más comunes: un `.git/` expuesto te entrega el código fuente completo de la aplicación.

```bash
# Verificar control de versiones y metadatos expuestos
ffuf -u https://target.com/FUZZ \
  -w <(echo -e ".git/HEAD\n.git/config\n.gitignore\n.svn/entries\n.hg/\n.bzr/\n.DS_Store\n.env\n.env.local\n.env.production") \
  -mc 200,403

# Si /.git/HEAD responde 200, dumpea el repo completo
# git-dumper https://target.com/.git/ ./loot   (herramienta externa)

# Archivos de CI/CD y despliegue que filtran secretos
ffuf -u https://target.com/FUZZ \
  -w <(echo -e ".gitlab-ci.yml\n.github/workflows/\nDockerfile\ndocker-compose.yml\n.npmrc\n.aws/credentials\nconfig.json\ncredentials.json") \
  -mc 200
```

> Un `.git/HEAD` que devuelve `200` es oro: con `git-dumper` reconstruyes todo el repositorio — código fuente, comentarios, claves hardcodeadas, lógica de auth, y a menudo credenciales en el historial de commits. Un `.env` o `.DS_Store` expuesto es el mismo tipo de regalo. Estos van siempre en tu primer barrido.
{: .prompt-tip }

---

## 4. VHost y Subdominios

```bash
# VHost fuzzing — descubre hosts internos sin registro DNS
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
  -u https://target.com/ \
  -H "Host: FUZZ.target.com" \
  -ac -fs <tamaño_baseline>

# Combinar con filtro por palabras cuando el tamaño varía
ffuf -w subdomains.txt -u https://target.com/ \
  -H "Host: FUZZ.target.com" -fw <palabras_baseline>

# VHost sobre IP directa (cuando ya tienes la IP de origen)
ffuf -w subdomains.txt -u http://1.2.3.4/ \
  -H "Host: FUZZ.target.com" -ac
```

> En VHost fuzzing, **el filtro lo es todo**. Manda primero una petición con un `Host:` basura, anota el tamaño/palabras de la respuesta por defecto, y filtra eso con `-fs`/`-fw`. Todo lo que difiera del default es un vhost real respondiendo distinto.
{: .prompt-warning }

---

## 5. Descubrimiento de Parámetros Ocultos

Los parámetros que no están enlazados en ningún lado son donde viven IDOR, inyección y toggles de debug.

```bash
# Parámetros GET ocultos (FUZZ en el nombre)
ffuf -u "https://target.com/page?FUZZ=test" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -fs <tamaño_base>

# Parámetros POST (form-urlencoded)
ffuf -u https://target.com/api/data -X POST \
  -d "FUZZ=test" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -w burp-parameter-names.txt -fc 401,403

# Parámetros en JSON
ffuf -u https://target.com/api/data -X POST \
  -d '{"FUZZ":"test"}' \
  -H "Content-Type: application/json" \
  -w burp-parameter-names.txt -fs <base>

# Detectar parámetros que cambian el comportamiento (debug, admin, test)
ffuf -u "https://target.com/page?FUZZ=1" \
  -w params.txt -mr "debug|admin|true|error"   # match por reflejo en respuesta
```

> Cuando buscas parámetros, el código de estado casi nunca cambia — todos devuelven `200`. La señal real es el **tamaño** o el **contenido** de la respuesta. Fija el baseline con un parámetro inventado, filtra ese tamaño, y lo que se desvíe es un parámetro que el backend *sí* procesó.
{: .prompt-info }

---

## 6. Fuzzing de Valores — IDOR y Enumeración

```bash
# Enumerar IDs secuenciales (IDOR clásico)
ffuf -u "https://target.com/api/user/FUZZ" \
  -w <(seq 1 10000) \
  -mc 200 -fs <tamaño_404>

# Fuzzear valores en parámetro con sesión
ffuf -u "https://target.com/profile?id=FUZZ" \
  -w <(seq 1 5000) \
  -b "session=COOKIE" \
  -mc 200 -ac

# Generar input dinámico con -input-cmd (UUIDs, rangos, formatos)
ffuf -u "https://target.com/doc/FUZZ" \
  -input-cmd 'seq 1000 2000' -mc 200
```

> `-w <(seq 1 10000)` usa process substitution de bash para generar la wordlist al vuelo — perfecto para enumerar IDs numéricos sin crear archivos. Para IDOR, compara los tamaños de respuesta: un objeto que existe pero no es tuyo suele devolver `200` con un tamaño distinto al de "no encontrado".
{: .prompt-tip }

---

## 7. Recon de APIs

Las APIs son la superficie de ataque moderna. Fuzzea endpoints, versiones, métodos y recursos anidados.

```bash
# Endpoints de API bajo un prefijo conocido
ffuf -u "https://target.com/api/v1/FUZZ" \
  -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -mc 200,201,401,403 -ac

# Versiones de API (a veces v2/v3 internas con menos protección)
ffuf -u "https://target.com/api/vFUZZ/users" \
  -w <(seq 1 5) -mc 200,401,403

# Métodos HTTP por endpoint (GET protegido, ¿PUT/DELETE no?)
ffuf -u "https://target.com/api/v1/user/1" \
  -X FUZZ -w <(echo -e "GET\nPOST\nPUT\nDELETE\nPATCH\nOPTIONS") \
  -mc all -fc 405

# Recursos anidados (descubre la jerarquía de la API)
ffuf -u "https://target.com/api/v1/FUZZ" \
  -w api-objects.txt -recursion -recursion-depth 2 \
  -H "Accept: application/json" -mc 200,401,403

# Documentación / esquema expuesto
ffuf -u "https://target.com/FUZZ" \
  -w <(echo -e "swagger.json\nopenapi.json\napi-docs\ngraphql\nactuator/mappings") \
  -mc 200
```

---

## 7b. Fuzzing Ofensivo — Probar Vulnerabilidades, No Solo Descubrir

ffuf no es solo para descubrimiento. Un cazador lo usa para *probar clases de vulnerabilidad* inyectando payloads en parámetros confirmados.

```bash
# Path traversal / LFI — fuzzear payloads de traversal en un parámetro
ffuf -u "https://target.com/download?file=FUZZ" \
  -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt \
  -mr "root:.*:0:0|DB_PASSWORD|\[boot loader\]"   # match contenido de /etc/passwd o win.ini

# Open redirect — payloads de redirección en parámetros de retorno
ffuf -u "https://target.com/redirect?url=FUZZ" \
  -w /usr/share/seclists/Fuzzing/open-redirect.txt \
  -mr "evil.com" -fc 404   # match si la redirección apunta a tu dominio

# SSRF — fuzzear esquemas/hosts internos en un parámetro que hace fetch
ffuf -u "https://target.com/fetch?url=FUZZ" \
  -w <(echo -e "http://127.0.0.1\nhttp://169.254.169.254/latest/meta-data/\nfile:///etc/passwd\nhttp://localhost:8080") \
  -mc all -mt ">3000"   # diferencias de tiempo/respuesta delatan SSRF

# SQLi basada en tiempo — payloads con sleep, match por tiempo de respuesta
ffuf -u "https://target.com/api?id=FUZZ" \
  -w /usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt \
  -mt ">5000"   # respuestas que tardan >5s = posible inyección de tiempo
```

| Técnica | Keyword va en | Cómo se detecta el hit |
|---------|---------------|------------------------|
| LFI / Path Traversal | Valor del parámetro de archivo | `-mr` contra contenido de `/etc/passwd` o `win.ini` |
| Open Redirect | Parámetro de retorno (`url`, `next`, `redirect`) | `-mr` contra tu dominio de control |
| SSRF | Parámetro que hace fetch server-side | `-mt` (tiempo) o callback en tu servidor |
| SQLi ciega por tiempo | Parámetro inyectable | `-mt ">5000"` (sleep en el payload) |

> El cambio mental: en discovery usas el **código** (`-mc`); en pruebas de vulnerabilidad usas el **contenido** (`-mr`) y el **tiempo** (`-mt`). Una respuesta que tarda 5s de más, o que contiene `root:x:0:0`, es la firma de la vulnerabilidad — no el status code. Combina esto con un Interactsh/Burp Collaborator para SSRF y XXE out-of-band.
{: .prompt-warning }

---

## 8. Fuzzing Autenticado — Por Sesiones

Aquí está la diferencia del pro: **la mayor parte de la superficie de ataque está detrás del login.** Fuzzear sin sesión solo ve la cáscara pública.

```bash
# Con cookie de sesión
ffuf -u "https://target.com/dashboard/FUZZ" \
  -w wordlist.txt \
  -b "session=eyJ...; csrf=abc123" \
  -mc 200,403 -ac

# Con token JWT en Authorization
ffuf -u "https://target.com/api/v1/FUZZ" \
  -w api-endpoints.txt \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIs..." \
  -H "Accept: application/json" \
  -mc 200,401,403

# Múltiples headers de sesión (token + CSRF + custom)
ffuf -u "https://target.com/admin/FUZZ" \
  -w wordlist.txt \
  -H "Authorization: Bearer TOKEN" \
  -H "X-CSRF-Token: CSRF_VALUE" \
  -H "X-Requested-With: XMLHttpRequest" \
  -mc 200,403

# Replay de los matches a Burp para inspección manual autenticada
ffuf -u "https://target.com/api/FUZZ" \
  -w endpoints.txt \
  -H "Authorization: Bearer TOKEN" \
  -replay-proxy http://127.0.0.1:8080 \
  -mc 200
```

### Mantener la sesión viva (tokens que expiran)

Cuando el token caduca a mitad del fuzzing, automatiza su refresco:

```bash
# -input-cmd puede invocar un script que devuelva un token fresco por petición
# (o re-genera el token periódicamente y reinyéctalo vía variable)
TOKEN=$(curl -s -X POST https://target.com/auth -d '{"u":"x","p":"y"}' | jq -r .token)
ffuf -u "https://target.com/api/FUZZ" -w list.txt \
  -H "Authorization: Bearer $TOKEN" -mc 200,403
```

> **Verifica que tu sesión sigue activa.** Si a mitad del fuzzing el token expira, empezarás a recibir `401` en todo y creerás que no hay nada. Manda una petición de control a un endpoint conocido cada cierto tiempo, o usa `-replay-proxy` para revisar en Burp que las respuestas siguen siendo las de un usuario autenticado.
{: .prompt-warning }

---

## 9. Fuzzing desde un Request Crudo (Burp → ffuf)

El flujo profesional: captura la petición en Burp, guárdala, marca el `FUZZ` y deja que ffuf la reproduzca con todos sus headers y cookies intactos.

```bash
# Guarda la request de Burp como request.txt y pon FUZZ donde quieras fuzzear
ffuf -request request.txt -request-proto https \
  -w wordlist.txt -mc 200,403 -ac
```

```text
# request.txt (ejemplo) — el FUZZ va en la ruta, parámetro o header
POST /api/FUZZ HTTP/1.1
Host: target.com
Authorization: Bearer eyJ...
Content-Type: application/json
Cookie: session=abc123

{"data":"test"}
```

> `-request` es la forma más fiel de fuzzear: heredas *exactamente* los headers, cookies y cuerpo de una petición real autenticada. Elimina el problema de "funciona en Burp pero no en ffuf" por headers faltantes. Es como trabaja un pentester serio.
{: .prompt-tip }

---

## 10. Modos de Ataque

```bash
# clusterbomb (default multi-wordlist): TODAS las combinaciones N×M
ffuf -u "https://t.com/FUZZ/FUZ2Z" \
  -w dirs.txt:FUZZ -w files.txt:FUZ2Z -mode clusterbomb

# pitchfork: empareja listas posición a posición (N peticiones)
ffuf -u "https://t.com/api/FUZZ" -d '{"id":"PARAM"}' \
  -w endpoints.txt:FUZZ -w ids.txt:PARAM -mode pitchfork

# sniper: una sola wordlist, recorre cada posición FUZZ de a una
ffuf -u "https://t.com/FUZZ/page?id=FUZZ" \
  -w wordlist.txt -mode sniper
```

| Modo | Lógica | Peticiones |
|------|--------|------------|
| `clusterbomb` | Producto cartesiano de todas las listas | N × M |
| `pitchfork` | Empareja listas en paralelo (1↔1, 2↔2) | N (la más corta) |
| `sniper` | Una lista, una posición a la vez | N × posiciones |

> Usa **pitchfork** cuando las listas están relacionadas (usuario↔password de una filtración), **clusterbomb** cuando quieres todas las combinaciones (dir × archivo), y **sniper** para probar un payload en cada punto de inyección por separado.
{: .prompt-info }

---

## 11. Filtrado Avanzado — El 80% del Arte

| Flag | Acción |
|------|--------|
| `-mc` / `-fc` | Match / filter por código de estado |
| `-ms` / `-fs` | Match / filter por tamaño (bytes) |
| `-mw` / `-fw` | Match / filter por número de palabras |
| `-ml` / `-fl` | Match / filter por número de líneas |
| `-mr` / `-fr` | Match / filter por regex (sobre el cuerpo) |
| `-mt` / `-ft` | Match / filter por tiempo de respuesta |
| `-ac` | Auto-calibración estándar |
| `-acc` | Auto-calibración con cadena custom |
| `-mmode` / `-fmode` | Combinar filtros con lógica `and`/`or` |

```bash
# Combinar filtros: excluir respuestas que sean 403 Y de 1234 bytes
ffuf -u https://t.com/FUZZ -w list.txt \
  -fc 403 -fs 1234 -fmode and

# Match por tiempo: detectar inyección basada en tiempo (sleep)
ffuf -u "https://t.com/api?id=FUZZ" \
  -w sqli-time.txt -mt ">5000"   # respuestas que tardan más de 5s
```

> Cuando un target devuelve `200` con tamaño variable a todo, ningún filtro simple funciona. Ahí entran los filtros **combinados** (`-fmode and`) y la calibración custom (`-acc`): defines una firma de "respuesta basura" con varias condiciones y filtras solo lo que la cumpla toda.
{: .prompt-warning }

---

## 12. Evasión de WAF y Control de Ritmo

```bash
# Ritmo controlado bajo un WAF
ffuf -u https://target.com/FUZZ -w list.txt \
  -t 10 -rate 20 -p 0.1-1.0 -ac

# Rotar User-Agent y añadir headers de "confianza"
ffuf -u https://target.com/FUZZ -w list.txt \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
  -H "X-Forwarded-For: 127.0.0.1" \
  -t 10 -rate 25

# A través de proxy (Burp, o cadena de proxies para rotar IP)
ffuf -u https://target.com/FUZZ -w list.txt \
  -x http://127.0.0.1:8080

# Detener el job si detectas baneo (muchos errores seguidos)
ffuf -u https://target.com/FUZZ -w list.txt -se -maxtime 600
```

| Flag | Descripción |
|------|-------------|
| `-t` | Hilos (baja a 10 contra WAF) |
| `-rate` | Límite global de req/s |
| `-p` | Delay entre peticiones (fijo o rango `0.1-1.0`) |
| `-x` | Proxy HTTP/SOCKS |
| `-se` | Stop on spurious errors |
| `-maxtime` | Tiempo máximo total del escaneo |
| `-maxtime-job` | Tiempo máximo por job de recursión |

### Manejar el rate-limit (429) y guardar evidencia

```bash
# Reintentos y stop si el target empieza a tirar 429 (te está baneando)
ffuf -u https://target.com/FUZZ -w list.txt \
  -sf -t 5 -rate 10 -p 0.5-1.5   # -sf: stop on all 403/429 (señal de baneo)

# Guardar el CUERPO de cada respuesta para análisis offline
ffuf -u https://target.com/FUZZ -w list.txt -mc 200 \
  -od ./responses/   # -od: output directory con cada respuesta completa
```

> Si empiezas a recibir `429 Too Many Requests`, no insistas — estás quemando tu IP y envenenando los resultados. Baja `-rate`, sube `-p`, y considera rotar IP vía `-x` con un pool de proxies. El `-od` guarda cada respuesta en disco: invaluable para revisar después *por qué* un endpoint respondió distinto sin re-lanzar el scan.
{: .prompt-warning }

---

## 13. Salida y Automatización

```bash
# Guardar en JSON para procesar después
ffuf -u https://target.com/FUZZ -w list.txt -mc 200,403 \
  -o resultados.json -of json

# Silencioso, solo resultados (para pipes)
ffuf -u https://target.com/FUZZ -w list.txt -mc 200 -s

# Múltiples formatos
ffuf -u https://target.com/FUZZ -w list.txt -o out.html -of html

# Ignorar comentarios de la wordlist y reanudar trabajos
ffuf -u https://target.com/FUZZ -w list.txt -ic   # ignore comments
```

---

## 14. El Flujo Completo de un Engagement Autenticado

```bash
#!/usr/bin/env bash
# Fuzzing autenticado por capas — SOLO contra objetivos autorizados
T="https://target.com"
COOKIE="session=eyJ..."
mkdir -p ffuf_out

# 1. Mapa público de directorios (sin sesión)
ffuf -u "$T/FUZZ" -w raft-medium-directories.txt \
  -recursion -recursion-depth 2 -mc 200,301,401,403 -ac \
  -o ffuf_out/01_dirs.json -of json

# 2. Archivos sensibles + backups
ffuf -u "$T/FUZZ" -w raft-medium-files.txt \
  -e .bak,.old,.zip,.sql,.env,.config -mc 200,403 -ac \
  -o ffuf_out/02_files.json -of json

# 3. Superficie AUTENTICADA (la que importa)
ffuf -u "$T/dashboard/FUZZ" -w wordlist.txt \
  -b "$COOKIE" -recursion -mc 200,403 -ac \
  -o ffuf_out/03_auth_dirs.json -of json

# 4. Parámetros ocultos en endpoints autenticados
ffuf -u "$T/api/data" -X POST -d '{"FUZZ":"test"}' \
  -H "Content-Type: application/json" -b "$COOKIE" \
  -w burp-parameter-names.txt -fs 0 \
  -o ffuf_out/04_params.json -of json

# 5. Endpoints de API
ffuf -u "$T/api/v1/FUZZ" -w api-endpoints.txt \
  -b "$COOKIE" -H "Accept: application/json" \
  -mc 200,201,401,403 -ac \
  -o ffuf_out/05_api.json -of json

echo "[+] Resultados en ffuf_out/ — ahora revisa cada match a mano."
```

---

## Errores Comunes (léelos antes de tu próximo target)

1. **Fuzzear sin `-ac` en apps modernas.** El catch-all/soft-404 te entierra en falsos positivos. La auto-calibración no es opcional.
2. **Filtrar los 403.** Prohibido ≠ inexistente. Es una ruta confirmada esperando un bypass.
3. **Solo fuzzear sin sesión.** El 80% de la superficie está detrás del login. Sin cookie/token, ves la cáscara.
4. **Dejar morir el token.** Si expira a mitad del scan, todo da `401` y creerás que no hay nada. Verifica la sesión periódicamente.
5. **Usar códigos cuando deberías usar tamaño.** En descubrimiento de parámetros y valores, el `200` no cambia — el tamaño sí.
6. **Wordlist equivocada para el stack.** Listas `.php` contra una app Java no encuentran nada. Ajusta extensiones al fingerprint.
7. **Modo de ataque equivocado.** Clusterbomb cuando querías pitchfork dispara N×M peticiones inútiles y te delata ante el WAF.

> **El hilo conductor:** ffuf es un bisturí, no una escopeta. Decide qué buscas, pon el `FUZZ` exactamente ahí, elige el modo de ataque correcto, autentica si la superficie lo requiere, y filtra hasta que solo quede señal. La herramienta es trivial; el criterio de dónde apuntar y cómo leer la respuesta es lo que encuentra el bug.
{: .prompt-info }
