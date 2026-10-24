# Auditoría de seguridad — Signal-Android 8.33.1

**Commit auditado:** `16f1384` ("Bump version to 8.33.1"), rama `arena/a628160e-signal-android`
**Fecha:** 2026-10-24 · **Alcance:** todo el código del repositorio (6.464 ficheros Kotlin/Java, 55 manifiestos, gradle)

## Resumen ejecutivo

> **Actualización (2026-10-24, segunda pasada):** un reporte externo aportado tras la primera
> auditoría señalaba un **crash remoto zero-click vía `DataMessage.Payment.Notification`** (F0 abajo).
> La traza fue verificada eslabón a eslabón contra este código y **es real (severidad Alta)**; ya está
> corregida en esta rama. Mi primera pasada —basada en Semgrep + greps por patrones— no lo detectó
> porque es un bug de *guarda de estado ausente a través de una cadena asíncrona de jobs*, invisible
> para reglas sintácticas. Queda constancia honesta de ello: «0 riesgos» absolutos no existen en
> ningún software (y libsignal en Rust, RingRTC/WebRTC, SQLCipher y el SO quedan fuera de este repo).
>
> **Resumen:** no se encontraron vulnerabilidades de confidencialidad/integridad (sin robo de datos,
> sin RCE, sin bypass de E2EE). Se encontraron **1 Alta (F0, DoS remoto), 2 Medias y 4 Bajas, todas
> corregidas en esta rama**, más 1 dependencia obsoleta que requiere actualización con build
> (documentada, no aplicada a ciegas porque rompería la verificación de dependencias).

### Hallazgos y estado

| # | Severidad | Hallazgo | Estado |
|---|-----------|----------|--------|
| F0 | **Alta** | **Crash remoto zero-click no autenticado** vía `DataMessage.Payment.Notification`: sin guarda de «pagos activados», una notificación de pago MobileCoin encola `PaymentTransactionCheckJob`, que llama a `Payments.getWallet()` → NPE por entropía nula → `Result.fatalFailure` → `JobRunner` relanza y mata el proceso. Afecta a todo usuario que nunca activó pagos | ✅ Corregido |
| F1 | **Media** | Backup Android: sin `dataExtractionRules` y `onFullBackup()` por defecto copiaría todo el directorio de datos si un transporte full/D2D lo invocara | ✅ Corregido |
| F2 | **Media** | Exportación de chat en texto plano (mensajes descifrados) persistía indefinidamente en caché **externo** | ✅ Corregido |
| F3 | Baja | `BackupRecordInputStream`: longitudes no autenticadas usadas como tamaño de asignación (OOM/crash al restaurar backup corrupto o con contraseña errónea); `validateFrame` asumía lecturas completas | ✅ Corregido |
| F4 | Baja | `MasterCipher.verifyMacFor/getMacFor` (código muerto) registraban MACs y el contenido en claro en logs; comparación MAC no constante | ✅ Corregido |
| F5 | Baja | `CallLinks.parseUrl` registraba la URL completa (contiene la clave raíz del enlace de llamada) | ✅ Corregido |
| F6 | Baja | `ExternalNavigationHelper`: el `browser_fallback_url` de una página 3DS/PayPal se lanzaba vía `Intent.parseUri` sin restringir esquema | ✅ Corregido |
| F7 | Baja | jackson-databind **2.12.0** (2020): afectado por CVE-2020-36518 / CVE-2022-42003 / CVE-2022-42004 (DoS por anidamiento). Sin *default typing* → no hay RCE | ⚠️ Documentado (requiere regenerar `verification-metadata.xml` con Gradle) |

---

## Metodología

1. **Inventario y superficie de ataque:** los 55 `AndroidManifest.xml` (app + flavors + 50 módulos),
   componentes `exported=true`, providers, servicios enlazables, receivers, reglas de backup,
   `file_provider_paths.xml`, build types, flags de release (`minify`, `debuggable`).
2. **Escaneo automatizado:** Semgrep 1.182 con 327 reglas (`java/lang/security`, `java/android`,
   `kotlin/lang/security`, `generic/secrets`, set completo Kotlin/Java en 2ª pasada) sobre
   `app/src/main + core + lib + feature` (8.104 ficheros, 99,9% de líneas parseadas). 197 hallazgos
   brutos → triados uno a uno (ver §4).
3. **Búsquedas dirigidas (grep) por clase de vulnerabilidad:** TLS bypass (TrustManager/HostnameVerifier),
   cripto débil (DES/ECB/MD5/SHA1/`Random`), `Cipher.getInstance` (los 34 sitios), inyección SQL
   (`rawQuery`/`execSQL` concatenados, 115 `rawQuery` revisados), WebView (`addJavascriptInterface`,
   `evaluateJavascript`, `loadUrl`), Zip-Slip, carga dinámica de código (`DexClassLoader`,
   `Runtime.exec`), deserialización Java/Jackson, XXE, intent redirection (`parseUri`,
   `getParcelableExtra` de Intents), PendingIntent mutables, `MODE_WORLD_*`, secretos hard-codeados,
   logging de cuerpos/tokenes, clipboard.
4. **Revisión manual de los puntos calientes:** actividades exportadas y deep links
   (`DeepLinkEntryActivity`, `DeviceProvisioningActivity`, `ShareActivity`, `AppSettingsActivity`,
   `ShortcutLauncherActivity`, `VoiceCallShare`, stickers), `PassphraseRequiredActivity`,
   providers (`PartProvider`, `BlobContentProvider`/`BlobProvider`, `AvatarProvider`, FileProvider),
   auto-update de APK (`ApkUpdateJob/Installer`), importadores de backup (v1 SQL y v2 archivo),
   `AttachmentCipherInputStream`, transferencia entre dispositivos (TLS autofirmado + SAS),
   `KeyStoreHelper`, `SignalBackupAgent`, parsers de enlaces (grupo/proxy/signal.me/call links),
   FCM, notificaciones (RemoteReply), JNI (único fichero C++) y WebViews de pago (Stripe/PayPal/Captcha).
5. **Dependencias:** revisión completa de `gradle/libs.versions.toml` (versiones con CVE conocidos)
   y de la cadena de suministro (`verification-metadata.xml` con SHA-256 fijados).

No se pudo compilar ni ejecutar tests en el entorno (sin JDK/Android SDK y sin acceso a
dl.google.com/mavenCentral); las correcciones son quirúrgicas, se verificó su sintaxis volviendo a
parsear cada fichero editado con Semgrep y revisando el diff completo.

---

## 1. Hallazgos corregidos

### F0 (Alta) — Crash remoto zero-click vía `DataMessage.Payment.Notification`
**Dónde:** `messages/DataMessageProcessor.kt:657-717` (`handlePayment`),
`jobs/PaymentTransactionCheckJob.java:55-92`, `payments/Payments.java:33-40` (`getWallet()`),
`jobs/BaseJob.java:33-35`, `jobmanager/JobRunner.java:71-78`.

**Traza verificada en este código** (reporte externo, confirmado punto por punto):
1. `EnvelopeContentValidator.validateDataMessage` no inspecciona `dataMessage.payment` (solo valida
   `syncMessage.outgoingPayment`), y `MessageContentProcessor.shouldIgnoreDataMessage` solo descarta
   remitentes bloqueados → un `DataMessage` con `Payment.Notification` de **cualquier** remitente
   (incluido desconocido/sin aceptar la solicitud de mensaje, vía push en segundo plano) llega a
   `handlePayment`.
2. `handlePayment` solo comprobaba que hubiera receipt: insertaba la fila
   (`PaymentTable.createIncomingPayment` → `PaymentMetaDataUtil.fromReceipt`, que solo exige un
   `Receipt` MobileCoin sintácticamente válido — fabricable sin fondos reales) y encolaba en el
   `finally` la cadena `PaymentTransactionCheckJob → PaymentLedgerUpdateJob`, **sin comprobar
   `SignalStore.payments.mobileCoinPaymentsEnabled()`**.
3. `PaymentTransactionCheckJob.onRun` (a diferencia de `PaymentLedgerUpdateJob.java:60`, que sí tiene
   la guarda) llamaba directamente a `payments.getWallet()`, que hace
   `Objects.requireNonNull(SignalStore.payments().getPaymentsEntropy())`. La entropía es `null` en
   cualquier cuenta que nunca activó pagos MobileCoin → `NullPointerException`.
4. `BaseJob.run()` convierte el `RuntimeException` en `Result.fatalFailure(e)`;
   `JobRunner` (línea 77) hace `throw result.getException()` sin try/catch en su hilo;
   `SignalUncaughtExceptionHandler` lo delega al handler del sistema → **muerte del proceso**.

Matices de impacto (por precisión): el job se marca fallido y se elimina **antes** del relanzamiento
(`jobController.onFailure`, línea 72), así que no hay bucle infinito de crash al reabrir — cada mensaje
malicioso = una muerte de proceso; la DoS sostenida exige reenviar (trivial para el atacante). Es un
impacto de **disponibilidad**, sin compromiso de confidencialidad/integridad: Alta, no Crítica.
`handlePaymentActivation` no necesita guarda (no toca wallet ni encola jobs; solo inserta un mensaje
de sistema, comportamiento legítimo).

**Corrección aplicada (defensa en profundidad, mismo patrón que `PaymentLedgerUpdateJob`):**
- `DataMessageProcessor.handlePayment`: si `!SignalStore.payments.mobileCoinPaymentsEnabled()`, se
  ignora el mensaje sin insertar ni encolar nada (un cliente legítimo jamás genera esta notificación
  hacia quien no tiene pagos: necesita su dirección de pago, que solo existe si los activó).
- `PaymentTransactionCheckJob.onRun`: guarda inicial
  `if (!mobileCoinPaymentsEnabled() || getPaymentsEntropy() == null) return;` — protege también las
  demás vías que encolan este job (`RecheckPaymentsMigrationJob`, y filas ya persistidas por el bug).

### F1 (Media) — Canal de extracción por backup completo / D2D no cerrado explícitamente
**Dónde:** `app/src/main/AndroidManifest.xml:77` (`allowBackup="true"`, `fullBackupOnly="false"`),
`absbackup/SignalBackupAgent.kt`.

Signal solo quiere backup *key-value* de los tokens SVR (`SvrAuthTokens`, documentados como
no-secretos: sin el PIN no sirven). Pero el manifiesto no declaraba `android:dataExtractionRules`
(API 31+) ni `android:fullBackupContent`, y `SignalBackupAgent` no sobrescribía `onFullBackup()`,
cuya implementación por defecto **copia todo el directorio de datos de la app**. En AOSP, con agente
KV + `fullBackupOnly=false` el sistema usa `onBackup()` (también para D2D, con el flag
correspondiente), pero herramientas de migración de OEM y cambios futuros del SO pueden invocar la
ruta *full*: en ese caso saldría del dispositivo la totalidad del dataset (BD SQLCipher, adjuntos
cifrados, blobs sellados). El impacto de confidencialidad está muy mitigado porque todo está cifrado
con claves aleatorias selladas en Android KeyStore (no transferibles), por eso **Media** y no Alta —
pero para una app con el modelo de amenaza de Signal es un canal innecesario (MASVS-STORAGE).

**Corrección aplicada:**
- `SignalBackupAgent.onFullBackup()` y `onRestoreFile()` sobrescritos como no-op con log.
- Nuevo `res/xml/data_extraction_rules.xml`: `<cloud-backup>` y `<device-transfer>` excluyen
  `root/file/database/sharedpref/external` por completo.
- Nuevo `res/xml/backup_rules.xml` (`fullBackupContent`, API ≤30) excluyendo todo.
- Ambas rutas solo gobiernan el backup por ficheros; el agente KV de tokens SVR **no se ve afectado**.

### F2 (Media) — La exportación de chat en claro quedaba en almacenamiento externo sin borrar
**Dónde:** `conversation/v2/ConversationViewModel.kt:807` (`startPlaintextExport`).

El ZIP de exportación (historial **descifrado** + media) se escribía en
`externalCacheDir/chat_exports/` y tras compartirlo **nunca se borraba** (solo se limpiaba al iniciar
la *siguiente* exportación). El caché externo es accesible vía USB/MTP y por apps con permisos de
almacenamiento, contradiciendo la garantía de cifrado en reposo de Signal.

**Corrección aplicada:** la exportación se escribe en `cacheDir` interno (sandbox), se añade
`<cache-path>` a `file_provider_paths.xml` para que el FileProvider pueda compartirla, y al iniciar
una exportación se purgan y eliminan las exportaciones heredadas de la carpeta externa.

### F3 (Baja) — Longitudes no autenticadas como tamaño de `new byte[]` en la restauración de backups
**Dónde:** `backup/BackupRecordInputStream.java` (constructor, `validateFrame()`, `readFrame()`).

La longitud de cabecera (texto plano) y la de cada frame (descifrada con AES-CTR **antes** de verificar
el MAC) se usaban directamente en `new byte[longitud]`. Un fichero de backup manipulado — o simplemente
una contraseña incorrecta, que produce una longitud pseudoaleatoria de hasta 2 GiB — provoca
`OutOfMemoryError`/crash en vez de un error limpio. Además `validateFrame()` asumía que un `read()`
corto marca el final del frame (frágil con streams SAF/red) y `readFrame()` no comprobaba
`longitud ≥ MAC` antes de recortarla. DoS local que requiere que la víctima intente restaurar ese
fichero: Baja.

**Corrección aplicada:** constante `MAX_FRAME_LENGTH` (64 MiB; los frames legítimos —una fila SQL,
una preferencia, un KV— son muy inferiores; los adjuntos van en streaming aparte) y `MAC_LENGTH`;
validación en cabecera, `readFrame()` y `validateFrame()`; `validateFrame()` reescrito con
`StreamUtil.readFully` (sin asumir lecturas cortas).

### F4 (Baja) — Código muerto que registraba secretos en `MasterCipher`
**Dónde:** `crypto/MasterCipher.java` (`verifyMacFor`, `getMacFor`, sin ningún llamador en todo el repo).

Esas funciones legacy escribían en log los valores MAC y **el contenido completo en claro**
(`"Macing: " + content`). Aunque hoy son inalcanzables, es código peligroso que no debe existir.
La comparación MAC activa (`verifyMacBody`) usaba `Arrays.equals` (tiempo no constante).

**Corrección aplicada:** métodos eliminados (con sus imports `Hex`/`Arrays` ya innecesarios) y
`verifyMacBody` pasa a `MessageDigest.isEqual`. El formato AES-CBC+HMAC-SHA1 de `MasterCipher` se
mantiene: es *encrypt-then-MAC* con MAC verificado antes de descifrar y solo se conserva para migrar
datos antiguos; cambiarlo rompería compatibilidad sin ganar seguridad real.

### F5 (Baja) — URL con clave raíz de call-link en logs
**Dónde:** `calls/links/CallLinks.kt:94,104,111,114` (`Log.w(TAG, "Invalid url: $url")`).

La URL de un call-link contiene la `CallLinkRootKey` (credencial *bearer*: quien la tiene puede entrar
a la llamada). El `Scrubber` global de Signal censura URLs antes de logcat y del log persistente, lo
que mitiga el problema, pero los secretos no deben pasar por el sistema de logs en absoluto.

**Corrección aplicada:** los mensajes ya no incluyen la URL, solo el motivo de invalidez.

### F6 (Baja) — Fallback de navegación externa sin restricción de esquema
**Dónde:** `components/settings/app/subscription/donate/stripe/ExternalNavigationHelper.kt`
(`attemptIntentLaunch`).

Cuando el intent principal (p. ej. app del banco en 3DS/iDEAL) no se puede lanzar, el código lanzaba
el extra `browser_fallback_url` —controlado por la página web del banco— mediante
`Intent.parseUri(..., URI_INTENT_SCHEME)`. Aunque `sanitizeWebIntent()` ya anulaba
componente/selector, quitaba los flags de cesión de URIs y forzaba `CATEGORY_BROWSABLE` (con tests),
el fallback se ejecutaba **sin segundo diálogo de confirmación** y admitía un `intent://` anidado o
esquemas arbitrarios. Por especificación, `browser_fallback_url` es una URL web.

**Corrección aplicada:** el fallback solo se lanza si su esquema es `http`/`https`, como
`ACTION_VIEW` + `CATEGORY_BROWSABLE` simple; cualquier otro esquema se rechaza con log y toast,
igual que un `ActivityNotFoundException`.

### F7 (Baja, documentada) — jackson-databind 2.12.0 obsoleta
**Dónde:** `gradle/libs.versions.toml` (`jackson-core`→`jackson-databind:2.12.0`, `jackson-module-kotlin:2.12.0`).

2.12.0 (2020) está afectada por CVE-2020-36518 (StackOverflow/DoS por JSON profundamente anidado;
arreglado en 2.12.6.1/2.13.2.1), CVE-2022-42004 y CVE-2022-42003 (este último solo con
`UNWRAP_SINGLE_VALUE_ARRAYS`). **No hay RCE:** ningún `ObjectMapper` del repo activa *default typing*
polimórfico. Jackson parsea JSON del servidor de Signal (TLS fijada), manifiestos de fuentes, config
de dispositivos y respuestas de Giphy vía proxy — un DoS requeriría JSON anidado malicioso desde una
de esas fuentes ya autenticadas. **No se aplica el bump a ciegas:** el repo fija SHA-256 de cada
artefacto en `gradle/verification-metadata.xml`, así que cambiar la versión sin regenerar ese fichero
(`./gradlew --write-verification-metadata sha256`) dejaría el build roto. Recomendación: subir a
**2.18.x** (par databind + module-kotlin) en un entorno con build y correr la suite completa; es la
única deuda de CVEs del catálogo (OkHttp 5.3.2, Okio 3.17, media3 1.9.1, libsignal 0.105.4, RingRTC
2.73.0, SQLCipher 4.17.0 y Conscrypt están al día).

---

## 2. Observaciones informativas (sin corrección, riesgo aceptado o por diseño)

- **`PRAGMA cipher_compatibility = 3; kdf_iter = 1`** (`SqlCipherDatabaseHook`): correcto en contexto —
  la «contraseña» SQLCipher es un secreto aleatorio de 256 bits sellado con AES/GCM por una clave
  Android KeyStore (`KeyStoreHelper`/`DatabaseSecretProvider`); el KDF no defiende contra fuerza
  bruta porque no hay nada que adivinar. No es una vulnerabilidad.
- **`res/xml/file_provider_paths.xml`** expone `<external-path path="."/>` (toda la SD). El provider es
  `exported=false` con `grantUriPermissions` y el único llamador de `FileProviderUtil.getUriFor` es la
  exportación de chat (ahora en caché interno), así que no es explotable hoy; se recomienda podar las
  rutas externas cuando se confirme que ningún flujo legacy las usa.
- **`PendingIntentFlags.mvc` por defecto `FLAG_MUTABLE`:** los PendingIntent se entregan solo al sistema
  (notificaciones, alarmas, callback de pin de shortcut) y los que aceptan *fill-in* (RemoteInput) lo
  necesitan. Endurecimiento posible: `immutable()` donde no haya fill-in. Sin impacto explotable hoy.
- **`PanicResponderListener`**: cualquier app puede emitir el broadcast PanicKit y provocar el bloqueo
  de la app (solo DoS/molestia; es la semántica de PanicKit y no borra datos).
- **Flavor `nightlyStaging`** declara `usesCleartextTraffic="true"`: solo build de staging nocturna,
  nunca release. La app release no define `networkSecurityConfig` (por defecto sin cleartext en
  targetSdk 36) y además todo el tráfico propio va sobre TLS con trust store propio.
- **Claves «públicas» en el repo** (`GIPHY_API_KEY`, `firebase_messaging.xml` con `google_api_key`):
  son identificadores de cliente pensados para ir en el binario (igual que en el upstream público),
  no secretos. El `ias.jks` es un keystore de test que no se distribuye.
- **El importador de backup v1 ejecuta SQL del fichero** (`FullBackupImporter.processStatement`):
  es el diseño del formato y cada frame va autenticado con HMAC-SHA256 (truncado a 10 bytes)
  **antes** de decodificarse/ejecutarse, con clave derivada de la contraseña que introduce el usuario.
  Un backup malicioso requiere convencer al usuario de restaurarlo con su contraseña, momento en el
  que, por definición, está aceptando sustituir su base de datos. No es una inyección explotable.

## 3. Áreas verificadas como seguras (evidencia negativa)

- **Red/TLS:** ningún TrustManager que acepte todo, ningún HostnameVerifier permisivo, ningún
  `onReceivedSslError → proceed()`. Los clientes del servicio usan trust store propio
  (`res/raw/whisper.store`, `SignalServiceTrustStore`) + `BlacklistingTrustManager` que delega en el
  validador real. Sin endpoints `http://` en código (solo comentarios/Javadoc). El
  `ApprovingTrustManager` de device-transfer captura el certificado autofirmado y la autenticación se
  completa con el SAS de 7 dígitos que el usuario compara en ambos dispositivos
  (`DeviceTransferAuthentication`, compromiso HMAC previo) — patrón correcto.
- **Cripto:** los 34 `Cipher.getInstance` son AES-GCM o AES-CBC/CTR siempre acompañados de
  HMAC-SHA256 verificado **antes** de liberar claro (`AttachmentCipherInputStream` verifica el MAC en
  una primera pasada; `EncryptedBackupReader.validateMac` precede al descifrado; adjuntos con MAC
  incremental libsignal). IVs aleatorios (`SecureRandom`), claves por-fichero derivadas por HMAC
  (`ModernEncryptingPartOutputStream`), `KeyStoreHelper` AES/GCM con IV generado por KeyStore.
  MD5 solo como huella de cambios de UI en colisiones de nombres (no seguridad); HmacSHA1 solo en
  TOTP estándar y en el `MasterCipher` legacy. `Random`/`Math.random` solo para jitter/colores.
- **Componentes exportados (25):** todos tras `PassphraseRequiredActivity` o con confirmación
  explícita (`DeviceProvisioningActivity` solo muestra diálogo y navega a ajustes; group/proxy/
  quick-restore muestran hojas de confirmación). `ShareActivity` distingue shares internos por
  `getLaunchedFromUid()` (API 34+). `MainActivity` ignora extras de conversación si la intent no
  viene de su propio componente (`isTrustedConversationIntent`). `PassphraseActivity` y el antiguo
  patrón `next_intent` ya ni están en el manifiesto. Servicios con binder sensibles
  (`KeyCachingService`, `GenericForegroundService`) son `exported=false`; el Authenticator devuelve
  `null` en todo. Sin widgets ni Autofill/CredentialProvider exportados.
- **Providers:** los 4 son `exported=false` + concesión temporal por URI. `PartProvider` rechaza si la
  app está bloqueada; `BlobProvider.buildFileName = Uri.encode(id)+".blob"` neutraliza path traversal
  (incluido en `delete`); `FileProviderUtil.delete` (borrado por path) es código inalcanzable.
- **SQL:** uso sistemático de parámetros (`?` + `SqlUtil.buildArgs`); los pocos `execSQL` con
  interpolación usan constantes internas (nombres de tabla/columnas o enteros) o nombres leídos de
  `sqlite_schema` local durante la restauración. FTS con `MATCH ?` parametrizado y saneamiento de la
  query. Nombre de adjunto remoto saneado con `File(name).name` antes de guardar a MediaStore
  (`SaveAttachmentUtil.sanitizeOutputFileName`).
- **WebView:** 4 superficies (Stripe 3DS, PayPal, Captcha ×2, visor de debuglogs). Sin
  `addJavascriptInterface` en ninguna. El visor de logs escapa con `JSONObject.quote()` todo lo que
  pasa a `evaluateJavascript`. `sanitizeWebIntent` (con tests) para URIs `intent://` de origen web.
- **Deep links:** parsers con igualdad estricta de host (`GroupInviteLinkUrl` con `java.net.URI`,
  `SignalMeUtil`/`SignalProxyUtil` con regex ancladas, `CallLinks` con prefijo completo
  `https://signal.link/call/#key=`): sin sufijos tipo `signal.group.evil.com`.
- **Auto-update (build website):** manifiesto de actualización por HTTPS con cliente propio; se
  verifica SHA-256 (`MessageDigest.isEqual`) del APK descargado antes de instalar **y** Android exige
  misma clave de firma; `setAppPackageName` en la sesión; el receiver exportado de
  `ACTION_DOWNLOAD_COMPLETE` (broadcast protegido) valida el `downloadId` esperado.
- **Logs/clipboard:** `Scrubber` aplicado en `AndroidLogger` y `PersistentLogger` (teléfonos, UUIDs,
  group-ids, IPs, URLs); `LogDatabase` también es SQLCipher; copies sensibles con
  `ClipDescription.EXTRA_IS_SENSITIVE` en `Util.copyToClipboard`.
- **Sin** carga dinámica de código, **sin** deserialización Java nativa de datos externos, **sin** XXE
  (no hay `DocumentBuilderFactory`/`SAXParserFactory`), **sin** Zip-Slip (no hay extracción de zips de
  terceros), único JNI de ~50 líneas sin manejo de buffers (`FileUtils.cpp`).
- **Spinner** (servidor HTTP interno de consulta de BD sobre NanoHTTPD, capaz de ejecutar SQL): solo
  se enlaza en el build type `spinner` (`"spinnerImplementation"(project(":lib:spinner"))`,
  hereda de `debug`). No llega a release — verificado.

## 4. Triaje del escaneo automatizado (Semgrep)

| Regla | N | Veredicto |
|---|---|---|
| `exported_activity` | 19 | Revisadas: intencionales y protegidas (ver §3) |
| `hardcoded-conditional` / `eqeq` | 95 | Estilo/correctitud, no seguridad |
| `gcm-detection` | 17 | Informativa: marca usos *correctos* de AES/GCM |
| `generic-api-key` (gitleaks) | 13 | FP: previews de Compose, traducciones, identificador de Firebase público |
| `weak-ssl-context` | 5 | FP: `SSLContext.getInstance("TLS")` + `Tls12SocketFactory` y trust managers reales |
| `cbc-padding-oracle` | 4 | FP en contexto: CBC **con HMAC verificado antes de descifrar** (adjuntos clásicos, provisioning, legacy MasterCipher) |
| `unencrypted-socket` | 2 | `IpExchange` (descubrimiento de IP local pre-TLS en device-transfer; la autenticación va después sobre TLS+SAS) |
| `use-of-md5` | 1 | Huella de UI, no seguridad |
| `unsafe-reflection` | 1 | `Class.forName(GZIPInputStream)` con nombre fijo en `Base64Tools` importado |
| `contains-bidirectional-characters` | 4 | Literales Unicode intencionales del `Linkifier` (detección de controles bidi) |
| `unquoted-attribute-var`/`var-in-href` | 33 | Plantillas Handlebars de **lib/spinner** (solo build interno) |
| `detected-google-api-key` | 2 | Identificador público de Firebase (ver §2) |

## 5. Cambios incluidos en esta rama

```
.../messages/DataMessageProcessor.kt                (F0: ignorar pagos si no están activados)
.../jobs/PaymentTransactionCheckJob.java            (F0: guarda enabled/entropía en onRun)
app/src/main/AndroidManifest.xml                    (+dataExtractionRules, +fullBackupContent)
app/src/main/res/xml/data_extraction_rules.xml      (nuevo)
app/src/main/res/xml/backup_rules.xml               (nuevo)
app/src/main/res/xml/file_provider_paths.xml        (+cache-path interno)
.../absbackup/SignalBackupAgent.kt                  (onFullBackup/onRestoreFile no-op)
.../conversation/v2/ConversationViewModel.kt        (exportación en caché interno + purga legacy)
.../backup/BackupRecordInputStream.java             (límites de frame + validateFrame robusto)
.../crypto/MasterCipher.java                        (fuera código muerto que loguea secretos; isEqual)
.../calls/links/CallLinks.kt                        (URLs con clave fuera de los logs)
.../donate/stripe/ExternalNavigationHelper.kt       (fallback solo http/https)
```

**Pendiente recomendado (fuera de esta rama por requerir build):** actualizar Jackson a 2.18.x
regenerando `verification-metadata.xml`, podar rutas externas de `file_provider_paths.xml` tras
confirmar que ningún flujo legacy las necesita, y migrar `PendingIntentFlags` a inmutable donde no
se necesite fill-in.
