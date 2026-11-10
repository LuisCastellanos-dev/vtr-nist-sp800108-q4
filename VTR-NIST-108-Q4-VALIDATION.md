# VTR-NIST-108-Q4-001 — Validación de compatibilidad y transición criptográfica

**Versión:** 0.1.0 — evidencia de laboratorio inicial  
**Fecha:** 2026-11-10  
**Organización:** Vector Telemetry Research (VTR)  
**Estado:** HECHO (fuentes identificadas y pruebas locales), INFERENCIA (interpretaciones delimitadas), PROYECCIÓN (validación externa y aplicaciones reales pendientes).  
**Relación:** Comentarios enviados por VTR el 2026-11-04 a la pregunta 4 del llamado público para NIST SP 800-108 Rev. 2. La recepción fue confirmada; **no se ha acreditado incorporación de recomendaciones ni respuesta técnica sustantiva**.

> **Regla de alcance.** Este artefacto es investigación independiente, no un documento de NIST. No certifica algoritmos, módulos, sistemas reales ni el cumplimiento de FIPS 140. Los casos de la matriz son sintéticos y las claves de laboratorio son públicas. La coincidencia documental o experimental no debe convertirse en una afirmación normativa sin fuente aplicable.

## 0. Resumen y pregunta verificable

La consulta oficial [NIST Q4][S1] pregunta qué problemas de compatibilidad o transición deben considerarse al revisar, desaprobar o retirar construcciones de derivación de claves. La aportación original de VTR solicitó separar aprobación criptográfica de factibilidad de despliegue, coordinar orientaciones con CMVP, evitar inferencias incorrectas entre Double-Pipeline y TLS 1.2, y publicar una matriz trazable por construcción.

**Pregunta VTR:** ¿Puede un tercero distinguir qué construcción opera realmente, qué documento gobierna su uso, cuál es su estado de validación y qué decisión de migración está justificada, sin confundir similitud algorítmica con dependencia normativa?

La entrega cubre **tres acciones**: A1, ejemplo reproducible; A2, separación de estados de sistemas heredados; A3, matriz auditable y criterios de aceptación. Se elige **un caso sintético, no una instalación industrial o bancaria real**. No se inicia un proyecto de implementación criptográfica ni se modifican KBK, Sentinel o el roadmap.

### Correspondencia con el comentario enviado

| Comentario original | Mejora experimental o documental | Artefacto | Estado |
|---|---|---|---|
| R-01: aprobación vs. viabilidad | A2: cuatro preguntas separadas y exigencia de fuente y vigencia | §3, matriz `SYN-03` | INFERENCIA (criterio propuesto) |
| R-02: coordinación CMVP | A2/A3: prueba negativa de certificado no verificado; procedimiento de consulta oficial | §3–4, `test_10` | HECHO en fixture; aplicación real pendiente |
| R-03: Double-Pipeline y TLS 1.2 | A1: funciones distinguidas, caso con entradas públicas, pruebas de cambio de contexto | §2, `probe.py`, `test_03–06` | HECHO en laboratorio; inferencia normativa limitada |
| R-04: matriz por construcción | A3: esquema sintético, reglas de rechazo y mapeo de evidencia | §4, `matrix_synthetic.json` | HECHO como prototipo, no matriz oficial |

## 1. Fuentes y alcance normativo

| ID | Documento/fuente primaria | Hecho respaldado | Qué **no** respalda |
|---|---|---|---|
| S1 | [NIST, llamada pública SP 800-108 Rev. 2, 2026-11-04][S1] | Pregunta 4 y evaluación de Double-Pipeline; plazo de comentarios hasta el 2026-12-18 | Ninguna decisión definitiva sobre Rev. 2, depreciación o fechas |
| S2 | [NIST SP 800-108r1-upd1][S2], §4.1 y §4.3 | Counter Mode y Double-Pipeline; formato estándar `Label || 0x00 || Context || [L]₂`, contador opcional en DP | Que el script haya pasado CAVP ni que una configuración empresarial sea aprobada |
| S3 | [RFC 5246][S3], §5 | Función TLS 1.2 `P_hash(secret, label || seed)` | Que todo producto con TLS 1.2 implemente la construcción DP de SP 800-108 |
| S4 | [CMVP, FAQ][S4], SG-6 y SG-7 | Validación de módulo distinta de la conformidad de un protocolo; término adecuado «validated» | Certificación o validación de un ejemplo de software |
| S5 | [CMVP, módulos validados][S5] | Certificados y políticas de seguridad; necesidad de comprobar versión, entorno y estado | Que un número declarado en una ficha sea suficiente |
| S6 | [CMVP, programmatic transitions][S6] | Existen reglas de transición y fechas que requieren fuente particular | Una fecha de transición para DP en la futura Rev. 2 |
| S7 | [NIST SP 800-82r3][S7] | OT exige considerar seguridad operacional, confiabilidad y rendimiento | Permiso general para mantener mecanismos inseguros |
| S8 | [RFC 4231][S8], §4.2 | Vector de referencia HMAC-SHA-256 de prueba | Validación de las funciones KDF de laboratorio por NIST |
| S9 | [CAVP][S9] | Validación algorítmica formal independiente de la prueba local | CAVP completado por VTR |

**Control de vigencia:** el llamado de Rev. 2 es *pre-draft*: no reemplaza por sí mismo SP 800-108r1-upd1. Cambios o fechas futuras deberán revisarse sobre documentos de NIST/CMVP publicados con posterioridad a esta captura.

## 2. Acción A1 — Caso reproducible con refutación

### 2.1 Hipótesis y contrahipótesis

**H-A1 (limitada):** la estructura del PRF TLS 1.2 y la variante HMAC Double-Pipeline descrita en SP 800-108r1-upd1 pueden modelarse con entradas y codificaciones concretas; su parecido estructural **no permite concluir** identidad normativa ni dependencia de una implementación real.

**C-A1 (a intentar refutar):** si soportar TLS 1.2 bastase para demostrar la presencia de SP 800-108 Double-Pipeline, no haría falta evidencia de la construcción, parámetros o versión implementada. La prueba `test_08` rechaza explícitamente esa inferencia en la matriz.

Las funciones de `probe.py` implementan **solo los casos de byte completos**, HMAC-SHA-256, longitud de salida `1..4096` bytes, entrada fija según el ejemplo de §4.3 y contador `r=32` cuando se habilita. No son implementaciones generales de SP 800-108; no tratan CMAC/KMAC, longitudes parciales en bits, todas las variantes de orden de campos, seguridad de claves ni los problemas criptanalíticos citados por NIST.

### 2.2 Contratos funcionales estudiados

**TLS 1.2:** RFC 5246 §5 define `P_hash(secret, seed)` con `A(0)=seed`, `A(i)=HMAC(secret,A(i−1))`, bloques `HMAC(secret,A(i)||seed)` y `PRF(secret,label,seed)=P_hash(secret,label||seed)`.

**SP 800-108 Double-Pipeline:** NIST §4.3 usa, en el orden por defecto, `fixed = label || 0x00 || context || [L]₂ (codificado en 32 bits)`, `A(0)=fixed`, `A(i)=HMAC(key,A(i−1))` y `K(i)=HMAC(key,A(i)||[i]₃₂||fixed)`, con el contador opcional para la variante HMAC; la salida concatena los bloques y recorta a `L` bits.

**Diferencia analizada:** la codificación y los parámetros de entrada de este experimento **son distintos**. Observar salidas distintas solo demuestra ese hecho para la fixture. No demuestra independencia criptográfica universal ni la inexistencia de dependencias de protocolo en sistemas concretos.

### 2.3 Entradas, procedimiento y resultados reales

La clave fija es un valor **sintético y público**, nunca una clave de producción. Se usa `Label = VTR-LAB`, `Context = asset-A`, `L = 512 bits` (64 bytes). La variante negativa modifica el contexto a `asset-B`, o elimina el contador de DP. Script, datos y pruebas se entregan junto con este Markdown.

Comandos para repetir en Linux o FreeBSD con Python 3.10+ (sin pip ni acceso a red):

```sh
cd vtr_sp800108_q4
python3 test_probe.py
python3 probe.py
sha256sum probe.py test_probe.py matrix_synthetic.json  # FreeBSD: sha256 -q <archivo>
```

**Ejecución inicial real:** Python 3.13.5 en Linux-6.18.57-x86_64-with-glibc2.41. `test_probe.py`: **15/15 pruebas superadas**. `probe.py`: **4/4 observaciones booleanas positivas y matriz de 3 filas validada**. Fuente primaria de esta afirmación: `evidence/test_log.txt` y `evidence/probe_results.json`, generadas por ejecución local.

| Serie experimental (64 bytes) | Prefijo hexadecimal observado (16 bytes) | Resultado |
|---|---|---|
| TLS 1.2 PRF/HMAC-SHA-256 | `56b8fd95b54d65bc81c42900857a7dc5` | HECHO |
| SP 800-108 DP/HMAC con contador de 32 bits | `99b20e50e9b7e6bd8b1a8263a9a4a1c1` | HECHO |
| SP 800-108 DP/HMAC sin contador | `eaa070d2aa4dda80a28bb801da411772` | HECHO |
| DP/HMAC con otro contexto | `6dc6782fefefed11c540ae5be037bc32` | HECHO |
| SP 800-108 Counter/HMAC | `d75fa9cc02b2b7238a61165255a8712f` | HECHO |

Se conserva la salida completa hexadecimal en el JSON de evidencia. Los prefijos no constituyen un estándar ni un vector publicado por NIST: **son resultados reproducibles de esta fixture**.

**Validación positiva anclada externamente:** `test_01` verifica el HMAC de RFC 4231 §4.2 (`b0344c61…e32cff7`). Sirve para detectar un error básico en la primitiva HMAC del entorno, no sustituye vectores oficiales de KDF ni revisión de código independiente.

**Pruebas negativas:** `test_08` intenta inferir una KDF de SP 800-108 a partir de TLS 1.2; `test_09` introduce un estado normativo `APPROVED` sin fuente; `test_10` inventa validación CMVP; `test_11` adelanta un despliegue; `test_12` elimina evidencia de implementación; `test_13` duplica IDs; `test_14` viola límites del laboratorio. Todas son detectadas por el control o generan rechazo de entrada.

**Límites explícitos:** sin vector externo específico de SP 800-108 para validar toda la KDF; sin prueba independiente en FreeBSD; sin ejecución real TLS de red; sin módulo CMVP, producto industrial o entorno de producción; sin evaluación de seguridad de PRF. **No promueve una afirmación de conformidad.**

## 3. Acción A2 — Estados separados para sistemas heredados

### 3.1 Cuatro preguntas que jamás deben reducirse a un solo «compliant»

| Dimensión | Pregunta que debe responderse | Evidencia adecuada | Si falta evidencia |
|---|---|---|---|
| Implementación | ¿Qué KDF, variante, parámetros y servicio están presentes realmente? | Código, configuración, trazas instrumentadas, prueba de fabricante o binario examinado | `NOT_EVIDENCED` |
| Normativa | ¿Qué versión de SP 800-108 y qué texto aplican a esa construcción, con qué fechas y condiciones? | Publicación y sección exactas, transición CMVP/CAVP vigente, fecha de consulta | `NOT_DETERMINED` |
| Validación | ¿Qué módulo, versión, entorno y servicio figuran en el certificado vigente? | Certificado CMVP y *Security Policy* oficiales, estado de validación y vínculo con servicio | `NOT_EVIDENCED` |
| Despliegue | ¿Puede actualizarse sin comprometer los requisitos operativos, y quién autoriza el riesgo residual? | Plan de cambios, pruebas de interoperabilidad, ventanas, responsable de aceptación, evidencia de rollback | `PENDING_OFFICIAL_APPLICABILITY_REVIEW` |

**Límites de vocabulario:** «compatible» no significa «aprobado»; «algoritmo implementado» no significa «algoritmo validado»; «módulo validado» no significa que todas sus configuraciones o productos finales estén validados; «legacy use» solo puede utilizarse cuando la fuente aplicable lo establece expresamente. Un entorno que necesita continuidad operativa no adquiere una exención criptográfica automática. [S4][S5][S6][S7]

### 3.2 Ejemplos sintéticos, no inventario real

`SYN-01`: servicio que declara TLS 1.2. No se puede inferir que implemente la construcción Double-Pipeline de SP 800-108. La evidencia de protocolo y la de KDF se deben buscar por separado.

`SYN-02`: implementación explícita de DP/HMAC en el script de laboratorio. Existe evidencia de ejecución **sintética**, pero ningún certificado CMVP, condición de aprobación ni despliegue real queda demostrado.

`SYN-03`: equipo OT hipotético de larga vida útil. Su necesidad de mantenimiento planificado es una **proyección operativa**, no evidencia de una transición permitida o excepción normativa.

### 3.3 Condiciones de aceptación para un activo real

Una futura evaluación solo podrá elevarse de `NOT_EVIDENCED` cuando un revisor identifique: inventario verificable del producto, KDF y parámetros realmente utilizados; fuente normativa y versión aplicables al servicio; certificados y *Security Policy* del módulo concreto (si se declara validación); condiciones y fechas de transición tomadas del documento correcto; y resultado operativo de prueba de migración y rollback. El resultado no puede concluirse a partir de la marca del producto, su soporte de TLS ni de un laboratorio sintético.

## 4. Acción A3 — Matriz auditable de transiciones

### 4.1 Esquema y criterio de vinculación

Archivo: `matrix_synthetic.json`. El diseño restringido de laboratorio exige por fila: identificador, protocolo, KDF afirmada, evidencia de implementación, estado normativo, fuente normativa, afirmación CMVP, certificado, entorno operativo, decisión de despliegue, fuente de decisión, acción requerida y estado VTR. Se usan estados explícitos; **no se usan valores `null` ni campos omitidos**.

Para uso real, antes de poder afirmar `GATE-CONFIRMED`, ampliar el esquema con:

| Campo futuro | Evidencia que debe sostenerlo |
|---|---|
| `construction_variant` y `parameters` | Declaración de algoritmo exacta, modo, PRF, IV, contador, codificación |
| `standard_version`, `normative_clause`, `retrieved_at` | Documento, sección e instante de consulta verificables |
| `status`, `effective_date`, `transition_conditions` | Fuente normativa o CMVP identificada; fechas exactas, nunca supuestas |
| `cavp_validation_id` | Ficha y contexto del certificado algorítmico, si aplica |
| `cmvp_module_cert`, `security_policy_revision`, `validated_environment`, `service_id` | Entrada oficial CMVP y alcance del servicio |
| `deployed_fingerprint`, `vendor_evidence`, `change_ticket` | Identificación de módulo y servicio realmente ejecutados |
| `rollback_test_id`, `risk_acceptance_owner`, `decision_date` | Pruebas operativas y autorización humana documentadas |
| `source_hash`, `test_report_hash`, `reviewer_id`, `claim_state` | Integridad, reproducción y no autoría de la revisión |

**Verificador actual:** `check_matrix()` falla ante KDF declarada sin implementación, supuesta aprobación sin fuente, certificados ficticios, inferencia TLS → DP, despliegues decididos sin respaldo, campos faltantes e IDs duplicados. Es un validador de **evidencia mínima para fixtures**, no un motor de decisiones regulatorias.

### 4.2 Mapa trazabilidad: requisito → prueba → evidencia → estado

| ID VTR | Afirmación / requisito | Fuente de criterio | Prueba / evidencia | Estado verificable | Gate pendiente |
|---|---|---|---|---|---|
| VTR-Q4-REQ-01 | Distinguir semántica TLS PRF y DP bajo entradas especificadas | S2 §4.3; S3 §5 | `test_02–06`, `probe_results.json` | **HECHO local** | Validación externa de la KDF completa |
| VTR-Q4-REQ-02 | Comprobar primitiva HMAC con vector publicado | S8 §4.2 | `test_01` | **HECHO local** | Reproducción por tercero |
| VTR-Q4-REQ-03 | TLS 1.2 no prueba por sí solo uso de SP 800-108 DP | S1; S3; S4 SG-6 | `SYN-01`, `test_08` | **INFERENCIA normativa + control local HECHO** | Analizar un producto real con evidencia |
| VTR-Q4-REQ-04 | Estado normativo separado de KDF implementada | S1, S2, S6 | `SYN-02`, `test_09` | **HECHO como regla de fixture** | Status oficial futuro de Rev. 2 |
| VTR-Q4-REQ-05 | Validación del módulo distinta de validación del algoritmo/protocolo | S4, S5, S9 | `test_10`, `matrix_synthetic.json` | **HECHO como regla de fixture** | Corroboración de certificado específico |
| VTR-Q4-REQ-06 | Sin aprobación de despliegue por defecto | S5, S7 | `SYN-03`, `test_11` | **HECHO como regla de fixture** | Pilotaje y aprobación de riesgo real |
| VTR-Q4-REQ-07 | Integridad y unicidad de registros | Política interna VTR, regla de evidencia | `test_12–14`, SHA-256 en manifiesto | **HECHO local** | Revisión independiente de evidencias |
| VTR-Q4-REQ-08 | Evidencia reproducible de principio a fin | VTR-METH-001 / Evidence Policy | Código, logs, fixture, SHA-256 | **HECHO local** | FreeBSD + segundo revisor |

### 4.3 Estados de cierre (no confluir)

**GATE-LOCAL:** fuentes verificadas, 15 pruebas locales, experimentos y fixtures preservados. **Alcanzado.**  
**GATE-CROSS-PLATFORM:** ejecución equivalente en FreeBSD, verificación de salida y hashes. **PENDIENTE.**  
**GATE-INDEPENDENT:** tercero reproduce y revisa condiciones/atribución sin ser el autor. **PENDIENTE.**  
**GATE-REAL-WORLD:** evaluación de producto/servicio y certificado real con fuentes CMVP aplicables. **FUERA DE ALCANCE actual.**  
**GATE-NORMATIVE-CHANGE:** NIST emite texto nuevo y una comparación documentada identifica cambios. **PENDIENTE DE FUTURO DOCUMENTO.**

No hay cierre global `GATE-CONFIRMED` ni conclusión de seguridad para SP 800-108 Rev. 2.

## 5. Inserción explícita de metodología VTR

**Secuencia operacional:** *Lab → Hypothesis → Evidence → Reproduction → Conclusion*. En este caso, una afirmación solo pasa a **HECHO** si se ejecuta una prueba que hubiera podido refutarla y se conserva una salida revisable. Las hipótesis sobre una futura guía de NIST permanecen como **PROYECCIÓN**.

**CAPA 0.1 — Tricotomía:** separar evidencia de **implementación** (bytes/código), evidencia **normativa** (fuente aplicable y vigencia) e **impacto** (resultado operativo real, actualmente no observado). Ninguna puede sustituir a otra.

**No-autoría / CAPA 8:** la siguiente revisión de este artefacto debe realizarla un tercero distinto de quien produjo el script y las conclusiones. La ejecución local no satisface revisión independiente.

**Zero Presumption / regla de no-null:** no presuponer que TLS implica DP; no rellenar fechas o certificados desconocidos; declarar `NOT_EVIDENCED`, `NOT_DETERMINED` o `PENDING_OFFICIAL_APPLICABILITY_REVIEW` de forma explícita. No ascender estados por correspondencias textuales o por ausencia de errores.

**Dimensiones de reproducibilidad:** `ΔA` (otro revisor), `ΔC` (FreeBSD/versión de Python), `ΔT` (fecha/edición de la norma) y `ΔK` (separación de aporte propio y cambios de terceras partes). Ninguna de estas variaciones se ha validado globalmente.

**Hipótesis refutable obligatoria:** si una nueva prueba no puede producir un resultado contrario bajo condiciones controladas, no debe utilizarse para promocionar una afirmación. Ejemplos: un certificado inexistente debe ser rechazado; un cambio de contexto debe quedar registrado; una variante DP erróneamente declarada como validada no debe superar el gate.

## 6. Procedimiento de reproducción independiente y evidencia

**Paquete entregado:** `probe.py`, `test_probe.py`, `matrix_synthetic.json`, `evidence/probe_results.json`, `evidence/test_log.txt`, `SHA256SUMS.txt` y este Markdown. No contiene llaves privadas ni registros reales de módulos. Nunca debe procesar secretos de producción.

**Entorno inicial:** Python 3.13.5, Linux-6.18.57-x86_64-with-glibc2.41; implementación HMAC-SHA-256 de la biblioteca estándar `hmac`/`hashlib`; sin dependencias Python externas. En FreeBSD usar `sha256 archivo` en lugar de `sha256sum` si no está instalado coreutils.

**Trazabilidad del código:** SHA-256 inicial de `probe.py`: `81fe4818cadce65cbb43b9945d6a933f3a7d1aea1d20a79b05bfbf3d06e55237`. Los demás checksums están en `SHA256SUMS.txt`. El JSON de resultados vincula `script_sha256` con la ejecución. **No hay firma digital, sello de tiempo confiable ni inmutabilidad forense**; los SHA-256 identifican bytes de archivos archivados, no acreditan su origen.

**Procedimiento del segundo revisor:** descargar/descomprimir; comprobar hashes del manifiesto; revisar inputs sintéticos; ejecutar pruebas; volver a generar `probe_results.json`; comparar observaciones y salidas de KDF en las mismas condiciones; cambiar una condición cada vez y documentar la diferencia; presentar un informe firmado o verificable con entorno, fecha, fallos y límites. Si se modifica el código, emitir manifiesto nuevo y no sobreescribir silenciosamente el original.

**Criterios adicionales de cierre:** añadir un vector externo de KBKDF/SP 800-108 apropiado a la variante y esquema probados (pendiente de selección/verificación), reproducir en FreeBSD 14.5 y obtener una revisión independiente de consistencia normativa. Una prueba satisfactoria de HMAC (RFC 4231) no basta para certificar la implementación DP.

## 7. Alcances, defectos conocidos y próximos gates

| ID | Pendiente o restricción | Acción de cierre | Prioridad |
|---|---|---|---|
| OPEN-01 | La KDF de demostración no está validada contra vector oficial de KBKDF | Obtener vector público con procedencia y adaptar prueba exacta | Alta |
| OPEN-02 | No existe reproducción independiente | Un revisor externo repite el laboratorio sin confiar en hashes declarados | Alta |
| OPEN-03 | Solo se ha ejecutado en Linux, no FreeBSD | Repetir con Python disponible en FreeBSD 14.5 y archivar resultado | Media |
| OPEN-04 | No hay material de certificados/activos reales | Seleccionar un caso público verificable, con permiso, certificado oficial y Security Policy | Condicional |
| OPEN-05 | Rev. 2 aún en consulta | Comparación normativa versionada cuando NIST publique texto sustantivo | Dependiente de NIST |
| OPEN-06 | El validador no constituye un esquema de cumplimiento | Definir un modelo separado y revisado para datos reales | No iniciar sin caso de uso |

**Decisión de alcance VTR:** conservar este resultado como **experimento metodológico de apoyo** a la respuesta pública de NIST y no convertirlo en una nueva línea prioritaria que desplace el cierre de KBK/RQ4. Cualquier extensión necesita criterio de aceptación medible, propietario y evidencia refutable.

## 8. Conclusiones controladas

**HECHO:** se ejecutaron las 15 pruebas locales; se obtuvo el vector HMAC de RFC 4231; las variantes ilustrativas difirieron bajo las entradas especificadas; la matriz sintética fue validada y rechazó las afirmaciones negativas ensayadas.

**INFERENCIA:** la separación de implementación, norma, validación y autorización de despliegue puede evitar errores de atribución como inferir dependencia de SP 800-108 a partir de soporte TLS 1.2. Las fuentes S1–S9 respaldan el principio, pero no sustituyen un inventario de sistema real.

**PROYECCIÓN:** una matriz por construcción podría mejorar la trazabilidad de transiciones reales si NIST o los operadores publican y mantienen la información necesaria. No se ha demostrado impacto operativo ni incorporación de la propuesta por NIST.

**Conclusión central:** *una cadena verificable de evidencia no convierte automáticamente en verdaderos los atributos normativos de un sistema; cada atributo necesita su propia fuente, alcance y prueba de aplicabilidad.*

---

## Referencias oficiales (consulta 2026-11-10)

[S1]: https://csrc.nist.gov/pubs/sp/800/108/r2/iprd
[S2]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1-upd1.pdf
[S3]: https://www.rfc-editor.org/rfc/rfc5246#section-5
[S4]: https://csrc.nist.gov/projects/cryptographic-module-validation-program/faqs
[S5]: https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules
[S6]: https://csrc.nist.gov/projects/cryptographic-module-validation-program/programmatic-transitions
[S7]: https://csrc.nist.gov/pubs/sp/800/82/r3/final
[S8]: https://www.rfc-editor.org/rfc/rfc4231#section-4.2
[S9]: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program
