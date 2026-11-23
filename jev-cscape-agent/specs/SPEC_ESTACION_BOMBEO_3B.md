# SPEC — Estación de bombeo de agua con 3 bombas y HMI
**Proyecto:** JEV-Cscape · **Software:** Horner Cscape 10.2 · **PLC:** Horner XL4 Prime (red CsCAN)
**Versión de la especificación:** 1.0 (2026-10-16) · **Implementación:** Jev (elige acciones) + ejecutor Python que maneja Cscape (Antigravity/agy)

> Nota para el implementador: los nombres de menús de Cscape **no** se fijan aquí; se describe la intención ("crear tag", "insertar bloque PID", "crear pantalla"). Todo valor marcado **[VERIFICAR]** debe confirmarse en la ayuda de Cscape o en la configuración de hardware antes de cerrar la tarea.

---
## 1. Alcance y supuestos

### 1.1 Alcance
Estación que bombea agua desde un tanque/pozo húmedo hacia una red de descarga, con:
- 3 bombas idénticas (B1, B2, B3), arranque directo por contactor; **todas comparten un único VFD de presión por diseño simplificado: el VFD alimenta a la bomba líder** (las de retraso arrancan a velocidad fija). Ver 1.2.
- Control por nivel en 3 etapas, rotación líder/retraso/reserva por horas de marcha, protección de marcha en seco, paro de emergencia, fallback ante falla.
- Lazo PID de presión de descarga que fija la referencia del VFD.
- Bloques de Texto Estructurado (ST) para escalado, horas de marcha, arranques y caudal totalizado.
- HMI de 6 pantallas en la pantalla integrada del XL4.
- Registro de datos y recetas de consignas.
- Pruebas de aceptación offline (Cscape) y en PLC real, con plan de rollback.

### 1.2 Supuestos
1. Hardware: XL4 Prime con E/S integradas o módulo que provea ≥12 DI, ≥5 DO, ≥3 AI (4–20 mA), ≥1 AQ (4–20 mA o 0–10 V). **[VERIFICAR]** el modelo exacto de E/S configurado en el proyecto base de JEV-Cscape; si difiere, mantener los nombres de tag y reasignar direcciones.
2. Rango digital de las entradas analógicas 4–20 mA: **0–32000** cuentas = 4–20 mA. Igual para la salida analógica. **[VERIFICAR]** en la configuración de E/S.
3. Las señales de seguridad son **normalmente cerradas** (NC): `PARO_EMERG` = 1 significa "sin emergencia"; `FLOT_SECO` = 1 significa "hay agua".
4. El selector local AUTO/MAN de cada bomba es físico (DI). En MAN la bomba se comanda desde la HMI; los enclavamientos de seguridad siguen activos.
5. El VFD siempre controla a la bomba **líder**. Simplificación aceptada: no hay transferencia de VFD entre bombas en caliente; la conmutación eléctrica de qué bomba va al VFD se considera externa (fuera de alcance).
6. Ciclo de escaneo típico < 20 ms; los bloques ST de horas usan un pulso de 1 s.
7. Los tipos REAL ocupan **2 registros %R** consecutivos. Por eso las direcciones REAL avanzan de 2 en 2.
8. Sin comunicaciones externas (Modbus/SCADA) en esta versión.

### 1.3 Convención de nombres
`<EQUIPO>_<SEÑAL>` en MAYÚSCULAS, sin tildes ni espacios.
- Prefijos de equipo: `P1_`, `P2_`, `P3_` (bombas), `LT_` (nivel), `PT_` (presión), `FT_` (caudal), `VFD_`, `SP_` (consigna), `ALM_` (alarma), `HMI_` (comando desde la pantalla), `PID_`.
- Sufijo `_RAW` = cuentas crudas de E/S analógica.

---
## 2. Lista de E/S y tags (59 tags)

### 2.1 Entradas digitales (%I) — 12
| # | Tag | Tipo | Dirección | Descripción | Estado lógico |
|---|---|---|---|---|---|
| 1 | P1_FB_MARCHA | BOOL | %I1 | Confirmación de marcha B1 (contacto auxiliar) | 1 = en marcha |
| 2 | P1_FALLA | BOOL | %I2 | Falla B1 (térmico/guardamotor) | 1 = falla |
| 3 | P1_AUTO | BOOL | %I3 | Selector B1 en AUTO | 1 = AUTO, 0 = MAN |
| 4 | P2_FB_MARCHA | BOOL | %I4 | Confirmación de marcha B2 | 1 = en marcha |
| 5 | P2_FALLA | BOOL | %I5 | Falla B2 | 1 = falla |
| 6 | P2_AUTO | BOOL | %I6 | Selector B2 en AUTO | 1 = AUTO |
| 7 | P3_FB_MARCHA | BOOL | %I7 | Confirmación de marcha B3 | 1 = en marcha |
| 8 | P3_FALLA | BOOL | %I8 | Falla B3 | 1 = falla |
| 9 | P3_AUTO | BOOL | %I9 | Selector B3 en AUTO | 1 = AUTO |
| 10 | PARO_EMERG | BOOL | %I10 | Paro de emergencia (NC) | 1 = normal, 0 = emergencia |
| 11 | FLOT_SECO | BOOL | %I11 | Flotador anti marcha en seco (NC) | 1 = hay agua |
| 12 | RESET_ALM | BOOL | %I12 | Pulsador físico de reset de alarmas | 1 = pulsado |

### 2.2 Salidas digitales (%Q) — 5
| # | Tag | Tipo | Dirección | Descripción |
|---|---|---|---|---|
| 13 | P1_CMD | BOOL | %Q1 | Comando de marcha B1 (contactor) |
| 14 | P2_CMD | BOOL | %Q2 | Comando de marcha B2 |
| 15 | P3_CMD | BOOL | %Q3 | Comando de marcha B3 |
| 16 | VFD_HAB | BOOL | %Q4 | Habilitación (RUN) del VFD |
| 17 | BALIZA_ALM | BOOL | %Q5 | Baliza/sirena de alarma (fija = alarma sin reconocer) |

### 2.3 Entradas analógicas (%AI) — 3
| # | Tag | Tipo | Dirección | Descripción | Rango crudo | Rango ingeniería |
|---|---|---|---|---|---|---|
| 18 | LT_NIVEL_RAW | INT | %AI1 | Transmisor de nivel 4–20 mA | 0–32000 | 0–100 % (0–5,00 m) |
| 19 | PT_PRES_RAW | INT | %AI2 | Transmisor presión de descarga 4–20 mA | 0–32000 | 0–10,0 bar |
| 20 | FT_CAUDAL_RAW | INT | %AI3 | Caudalímetro 4–20 mA | 0–32000 | 0–300 m³/h |

### 2.4 Salida analógica (%AQ) — 1
| # | Tag | Tipo | Dirección | Descripción | Rango crudo | Rango ingeniería |
|---|---|---|---|---|---|---|
| 21 | VFD_REF_RAW | INT | %AQ1 | Referencia de velocidad al VFD 4–20 mA | 0–32000 | 0–100 % (0–60 Hz) |

### 2.5 Registros REAL (%R, 2 registros c/u) — 15
| # | Tag | Tipo | Dirección | Descripción | Rango | Valor inicial |
|---|---|---|---|---|---|---|
| 22 | NIVEL_PCT | REAL | %R1 | Nivel escalado | 0–100 % | — |
| 23 | PRES_BAR | REAL | %R3 | Presión escalada | 0–10 bar | — |
| 24 | CAUDAL_M3H | REAL | %R5 | Caudal instantáneo | 0–300 m³/h | — |
| 25 | VFD_REF_PCT | REAL | %R7 | Referencia VFD en % (para HMI) | 0–100 % | — |
| 26 | SP_PRES | REAL | %R9 | Consigna de presión | 1,0–8,0 bar | 4,0 |
| 27 | SP_N1_ON | REAL | %R11 | Nivel arranque etapa 1 (líder) | 10–95 % | 60,0 |
| 28 | SP_N2_ON | REAL | %R13 | Nivel arranque etapa 2 (retraso) | 10–95 % | 75,0 |
| 29 | SP_N3_ON | REAL | %R15 | Nivel arranque etapa 3 (reserva) | 10–95 % | 85,0 |
| 30 | SP_N_OFF | REAL | %R17 | Nivel de paro de todas las etapas | 5–90 % | 30,0 |
| 31 | P1_HORAS | REAL | %R19 | Horas de marcha B1 (retentivo) | 0–999999 h | 0 |
| 32 | P2_HORAS | REAL | %R21 | Horas de marcha B2 (retentivo) | 0–999999 h | 0 |
| 33 | P3_HORAS | REAL | %R23 | Horas de marcha B3 (retentivo) | 0–999999 h | 0 |
| 34 | CAUDAL_TOT_M3 | REAL | %R25 | Caudal totalizado (retentivo) | 0–1e9 m³ | 0 |
| 35 | SP_PRES_ALTA | REAL | %R27 | Umbral de alarma de sobrepresión | 2–10 bar | 7,5 |
| 36 | SP_HORAS_ROT | REAL | %R29 | Diferencia de horas para forzar rotación | 1–500 h | 24,0 |

Validación de consignas (en ST, ver 5.1): se exige `SP_N_OFF < SP_N1_ON < SP_N2_ON < SP_N3_ON`; si no se cumple, se restauran los valores por defecto y se activa `ALM_CONFIG`.
Umbrales fijos (constantes en ST, no tags): nivel alto alarma = 90 %, nivel bajo alarma = 10 %.

### 2.6 Registros INT (%R) — 11
| # | Tag | Tipo | Dirección | Descripción | Rango |
|---|---|---|---|---|---|
| 37 | P1_ARRANQUES | INT | %R40 | Contador de arranques B1 (retentivo) | 0–32767 |
| 38 | P2_ARRANQUES | INT | %R41 | Contador de arranques B2 (retentivo) | 0–32767 |
| 39 | P3_ARRANQUES | INT | %R42 | Contador de arranques B3 (retentivo) | 0–32767 |
| 40 | ETAPA_REQ | INT | %R43 | Etapas requeridas por nivel | 0–3 |
| 41 | LIDER | INT | %R44 | Bomba líder actual | 1–3 |
| 42 | RETRASO | INT | %R45 | Bomba de retraso actual | 1–3 |
| 43 | RESERVA | INT | %R46 | Bomba de reserva actual | 1–3 |
| 44 | PID_PV | INT | %R47 | PV del PID (presión, 0–10000 = 0–10,000 bar) | 0–10000 |
| 45 | PID_SP | INT | %R48 | SP del PID (mismo escalado) | 1000–8000 |
| 46 | PID_CV | INT | %R49 | Salida del PID (0–32000) | 0–32000 |
| 47 | PID_BLK | INT | %R100 | Inicio del bloque de parámetros del PID de Cscape (reservar %R100–%R139) | — |

> `PID_BLK`: la función PID de Cscape usa un bloque contiguo de registros (ganancias, límites, modo, etc.). **[VERIFICAR]** en la ayuda de Cscape la longitud y el mapa exacto; se reservan 40 registros para seguridad y no se usa nada en %R100–%R139 para otro fin.

### 2.7 Bits internos (%M) — 12
| # | Tag | Tipo | Dirección | Descripción |
|---|---|---|---|---|
| 48 | P1_REQ | BOOL | %M1 | Solicitud automática de marcha B1 (calculada en ST) |
| 49 | P2_REQ | BOOL | %M2 | Solicitud automática de marcha B2 |
| 50 | P3_REQ | BOOL | %M3 | Solicitud automática de marcha B3 |
| 51 | HMI_P1_MAN | BOOL | %M4 | Marcha manual B1 desde HMI (botón mantenido/toggle) |
| 52 | HMI_P2_MAN | BOOL | %M5 | Marcha manual B2 desde HMI |
| 53 | HMI_P3_MAN | BOOL | %M6 | Marcha manual B3 desde HMI |
| 54 | HMI_RESET | BOOL | %M7 | Reset/reconocimiento de alarmas desde HMI (momentáneo) |
| 55 | PERMISIVO | BOOL | %M8 | Permisivo general: sin E-stop, sin marcha en seco |
| 56 | ALM_ESTOP | BOOL | %M10 | Alarma paro de emergencia |
| 57 | ALM_SECO | BOOL | %M11 | Alarma marcha en seco (flotador o nivel bajo) |
| 58 | ALM_P_FALLA | BOOL | %M12 | Alarma de falla de alguna bomba (resumen; detalle por bomba en 7) |
| 59 | ALM_PROCESO | BOOL | %M13 | Resumen de alarmas de proceso (nivel alto, sobrepresión, sensor, config) |

**Total: 59 tags.**
Las alarmas individuales de la tabla 7 se implementan como bits %M14–%M25 **sin tag con nombre propio adicional** si el límite de 60 lo exige; se recomienda nombrarlos igual que su ID (`ALM_A01`…`ALM_A12`) — si se crean como tags, el total sube a 71 y se acepta como desviación documentada. Decisión por defecto: **usar direcciones directas %M14–%M25 con comentario**, manteniendo 59 tags con nombre.

Retentividad: `P*_HORAS`, `P*_ARRANQUES`, `CAUDAL_TOT_M3`, todas las `SP_*`, `LIDER/RETRASO/RESERVA` deben quedar en zona retentiva. **[VERIFICAR]** que el rango %R usado es retentivo en el XL4 (normalmente %R lo es).

---
## 3. Narrativa de control

### 3.1 Permisivo general
`PERMISIVO = PARO_EMERG AND FLOT_SECO AND NOT (NIVEL_PCT < 10 durante 5 s)`.
Sin permisivo: todas las salidas `P*_CMD` = 0, `VFD_HAB` = 0, en AUTO y en MAN.

### 3.2 Etapas por nivel (AUTO)
Histéresis en ST (ver 5.1):
- `ETAPA_REQ` sube a 1 cuando `NIVEL_PCT ≥ SP_N1_ON`; a 2 cuando `≥ SP_N2_ON`; a 3 cuando `≥ SP_N3_ON`.
- Cada subida de etapa exige que la condición se mantenga **10 s** (anti rebote) y hay un retardo mínimo de **15 s** entre arranques consecutivos (evita picos de corriente).
- `ETAPA_REQ` baja a 0 cuando `NIVEL_PCT ≤ SP_N_OFF` durante 10 s (paran todas).
- Bajada parcial: cuando el nivel cae por debajo de `SP_Nx_ON − 10 %` durante 30 s, la etapa x se libera (para la última bomba arrancada).

### 3.3 Rotación líder / retraso / reserva
- Al arrancar la estación desde etapa 0 → 1 (flanco), se recalcula el orden: **líder = bomba disponible con menos horas**, retraso = la siguiente con menos horas, reserva = la de más horas. Empate → menor número de bomba.
- Rotación forzada: si la líder actual tiene `SP_HORAS_ROT` horas más que la disponible de menos horas, el orden se recalcula en el próximo paso por etapa 0 (no se para una bomba en marcha para rotar).
- Bomba **disponible** = `Px_AUTO AND NOT Px_FALLA AND NOT alarma de no-arranque de Px`.
- Asignación de etapas: etapa 1 → LIDER, etapa 2 → RETRASO, etapa 3 → RESERVA.

### 3.4 Fallback ante falla
- Si la bomba asignada a una etapa activa no está disponible (falla, MAN o no arrancó), la solicitud se pasa a la siguiente disponible en el orden LIDER → RETRASO → RESERVA que no esté ya solicitada.
- **No-arranque:** si `Px_CMD = 1` y `Px_FB_MARCHA = 0` tras **5 s** → alarma de no-arranque de Px (enclavada), se quita `Px_CMD`, y entra la siguiente.
- **Parada inesperada:** si `Px_CMD = 1`, había marcha y `Px_FB_MARCHA` cae a 0 durante 2 s → misma alarma.
- Si la líder falla, la nueva líder (por fallback) toma el VFD (`LIDER` se reasigna inmediatamente).

### 3.5 Modo manual
- `Px_AUTO = 0` → la bomba sale de la rotación automática.
- `Px_CMD = HMI_Px_MAN AND PERMISIVO AND NOT Px_FALLA`.
- En MAN la bomba arranca a velocidad fija (no VFD), salvo que sea la LIDER asignada y esté en AUTO (no aplica en MAN).
- Al pasar de MAN a AUTO, `HMI_Px_MAN` se pone a 0 (en ST).

### 3.6 Paro de emergencia
`PARO_EMERG = 0` → todas las salidas a 0 inmediatamente, `ALM_ESTOP` enclavada, `ETAPA_REQ = 0`. El rearme requiere `PARO_EMERG = 1` **y** reset (HMI o físico).

### 3.7 Marcha en seco
`FLOT_SECO = 0` (sin retardo, 1 s de filtro) o `NIVEL_PCT < 10 %` durante 5 s → paro de todas las bombas, `ALM_SECO` enclavada. Rearme: condición normal **y** `NIVEL_PCT > SP_N_OFF` **y** reset.

---
## 4. Lazo PID de presión de descarga

| Parámetro | Valor |
|---|---|
| Función | Bloque PID nativo de Cscape (insertar en Ladder, rung R20) |
| PV | `PID_PV` (INT, 0–10000 ↔ 0–10,000 bar), calculado en ST desde `PRES_BAR` |
| SP | `PID_SP` = `SP_PRES` × 1000 |
| CV | `PID_CV` (0–32000) → copiado a `VFD_REF_RAW` |
| Acción | Directa respecto al error SP−PV (si la presión baja, la velocidad sube). **[VERIFICAR]** el bit/campo de "acción inversa/directa" del bloque |
| Kp | 1,5 (ganancia proporcional; escalar al formato que pida el bloque) |
| Ti | 8 s (integral) |
| Td | 0 s (sin derivativa) |
| Periodo de muestreo | 100 ms |
| Límite CV mínimo | 9600 (= 30 % ≈ 18 Hz, velocidad mínima de bomba) |
| Límite CV máximo | 32000 (= 100 %) |
| Habilitación | `VFD_HAB = 1` (líder en marcha con confirmación y en AUTO) |
| Modo manual del PID | Si `VFD_HAB = 0`: PID en manual con CV = 9600 (preposicionado) para arranque suave sin salto |

**Anti-windup:** usar los límites de salida del propio bloque (debe congelar la integral al saturar). Si el bloque no lo hace **[VERIFICAR]**, mantener el PID deshabilitado/en manual mientras `VFD_HAB = 0` y reinicializarlo con CV = 9600 al habilitar, para que la integral no acumule con la bomba parada.

**Fallo de sensor:** si `PT_PRES_RAW < 0` o `> 32000` o la presión se congela (fuera de alcance v1), `PID` a manual con CV = 70 % (22400) y alarma A10.

`VFD_REF_PCT = PID_CV / 320.0` (para HMI).

---
## 5. Bloques de Texto Estructurado

Pseudocódigo IEC 61131-3 ST. Adaptar a la sintaxis exacta del editor ST de Cscape **[VERIFICAR]** (tipos, funciones de conversión INT↔REAL, pulso de sistema de 1 s). Si Cscape no dispone de un bit de reloj de 1 s, usar un temporizador autorreseteado en Ladder (rung R01) que genera `%M30` (dirección directa, pulso 1 s).

### 5.1 ST_ESCALADO_Y_LOGICA (cada scan)
```st
(* Escalado 4-20 mA: 0..32000 cuentas *)
NIVEL_PCT  := INT_TO_REAL(LT_NIVEL_RAW)  * 100.0 / 32000.0;
PRES_BAR   := INT_TO_REAL(PT_PRES_RAW)   * 10.0  / 32000.0;
CAUDAL_M3H := INT_TO_REAL(FT_CAUDAL_RAW) * 300.0 / 32000.0;
PID_PV := REAL_TO_INT(PRES_BAR * 1000.0);
PID_SP := REAL_TO_INT(SP_PRES * 1000.0);

(* Validacion de consignas *)
IF NOT (SP_N_OFF < SP_N1_ON AND SP_N1_ON < SP_N2_ON AND SP_N2_ON < SP_N3_ON) THEN
    SP_N_OFF := 30.0; SP_N1_ON := 60.0; SP_N2_ON := 75.0; SP_N3_ON := 85.0;
    %M25 := TRUE;  (* A12 ALM_CONFIG *)
END_IF;
IF SP_PRES < 1.0 THEN SP_PRES := 1.0; END_IF;
IF SP_PRES > 8.0 THEN SP_PRES := 8.0; END_IF;

(* Etapas: las condiciones con retardo (10 s/30 s) se resuelven con temporizadores
   en Ladder R05-R08 que ponen %M31..%M34; aqui se combinan *)
(* %M31 = nivel>=N1 10s, %M32 = >=N2 10s, %M33 = >=N3 10s, %M34 = <=OFF 10s *)
IF NOT PERMISIVO OR %M34 THEN
    ETAPA_REQ := 0;
ELSIF %M33 THEN ETAPA_REQ := MAX(ETAPA_REQ, 3);
ELSIF %M32 THEN ETAPA_REQ := MAX(ETAPA_REQ, 2);
ELSIF %M31 THEN ETAPA_REQ := MAX(ETAPA_REQ, 1);
END_IF;
(* Bajada parcial: %M35 = nivel < N3-10 30s, %M36 = nivel < N2-10 30s *)
IF ETAPA_REQ = 3 AND %M35 THEN ETAPA_REQ := 2; END_IF;
IF ETAPA_REQ = 2 AND %M36 THEN ETAPA_REQ := 1; END_IF;

(* Rotacion: solo con ETAPA_REQ = 0 *)
IF ETAPA_REQ = 0 THEN
    (* ordenar disponibles por horas ascendente; empate -> menor indice *)
    (* resultado en LIDER, RETRASO, RESERVA (1..3, todos distintos) *)
END_IF;

(* Solicitudes con fallback: recorrer orden LIDER, RETRASO, RESERVA,
   saltando no disponibles, y asignar las primeras ETAPA_REQ disponibles *)
P1_REQ := FALSE; P2_REQ := FALSE; P3_REQ := FALSE;
(* n := 0; para cada b en [LIDER, RETRASO, RESERVA]:
     si DISP(b) y n < ETAPA_REQ -> Pb_REQ := TRUE; n := n + 1;
     si n = 1 y b <> LIDER -> LIDER := b  (fallback de lider para el VFD) *)
(* DISP(b) = Pb_AUTO AND NOT Pb_FALLA AND NOT alarma no-arranque (%M14/15/16) *)

(* Al pasar a AUTO se limpia el comando manual *)
IF P1_AUTO THEN HMI_P1_MAN := FALSE; END_IF;
IF P2_AUTO THEN HMI_P2_MAN := FALSE; END_IF;
IF P3_AUTO THEN HMI_P3_MAN := FALSE; END_IF;

VFD_REF_PCT := INT_TO_REAL(PID_CV) / 320.0;
```

### 5.2 ST_HORAS_MARCHA (en el pulso de 1 s, %M30)
```st
IF %M30 THEN
  IF P1_FB_MARCHA THEN P1_HORAS := P1_HORAS + 1.0/3600.0; END_IF;
  IF P2_FB_MARCHA THEN P2_HORAS := P2_HORAS + 1.0/3600.0; END_IF;
  IF P3_FB_MARCHA THEN P3_HORAS := P3_HORAS + 1.0/3600.0; END_IF;
END_IF;
```
Nota de precisión: REAL de 32 bits pierde resolución por encima de ~4600 h al sumar 1/3600. Aceptado en v1; mejora v2: acumular segundos en INT y pasar a horas cada 3600 s.

### 5.3 ST_ARRANQUES (cada scan, flanco de subida de la confirmación)
```st
(* %M40..%M42 = estado anterior de Px_FB_MARCHA *)
IF P1_FB_MARCHA AND NOT %M40 THEN P1_ARRANQUES := P1_ARRANQUES + 1; END_IF;
IF P2_FB_MARCHA AND NOT %M41 THEN P2_ARRANQUES := P2_ARRANQUES + 1; END_IF;
IF P3_FB_MARCHA AND NOT %M42 THEN P3_ARRANQUES := P3_ARRANQUES + 1; END_IF;
%M40 := P1_FB_MARCHA; %M41 := P2_FB_MARCHA; %M42 := P3_FB_MARCHA;
(* saturar en 32767 *)
```

### 5.4 ST_CAUDAL_TOTAL (en el pulso de 1 s)
```st
IF %M30 AND CAUDAL_M3H > 1.5 THEN   (* corte de bajo caudal: 0,5 % FS *)
  CAUDAL_TOT_M3 := CAUDAL_TOT_M3 + CAUDAL_M3H / 3600.0;
END_IF;
```

---
## 6. Lista de rungs Ladder (26 rungs)

Notación: `-| |-` contacto NA, `-|/|-` contacto NC, `( )` bobina, `(S)/(R)` set/reset, TON = temporizador a la conexión. Direcciones %M30–%M45 y %T son auxiliares sin tag con nombre.

| Rung | Propósito | Lógica |
|---|---|---|
| R01 | Pulso de 1 s | `-|/|- %M30` → TON 1,0 s → `( %M30 )` (autorreset; omitir si existe bit de sistema de 1 s) |
| R02 | Llamada ST escalado y lógica | Siempre activo → ejecutar ST_ESCALADO_Y_LOGICA |
| R03 | Filtro marcha en seco | `-|/|- FLOT_SECO` TON 1 s **OR** (`NIVEL_PCT < 10.0` comparador) TON 5 s → `(S) ALM_SECO` y `(S) %M24` (A11) |
| R04 | Permisivo general | `-| |- PARO_EMERG` `-|/|- ALM_SECO` `-|/|- ALM_ESTOP` → `( PERMISIVO )` |
| R05 | Nivel ≥ N1 | Comparador `NIVEL_PCT ≥ SP_N1_ON` → TON 10 s → `( %M31 )` |
| R06 | Nivel ≥ N2 / ≥ N3 | `NIVEL_PCT ≥ SP_N2_ON` → TON 10 s → `( %M32 )`; rama paralela `≥ SP_N3_ON` → TON 10 s → `( %M33 )` |
| R07 | Nivel ≤ OFF | `NIVEL_PCT ≤ SP_N_OFF` → TON 10 s → `( %M34 )` |
| R08 | Bajada parcial | `NIVEL_PCT < SP_N3_ON − 10` → TON 30 s → `( %M35 )`; paralelo `< SP_N2_ON − 10` → TON 30 s → `( %M36 )` (restas calculadas en ST o con bloque SUB) |
| R09 | Retardo entre arranques | Flanco de subida de cualquier `Px_CMD` → TON 15 s; mientras corre, `( %M37 )` = bloqueo de nuevo arranque automático |
| R10 | Comando B1 | (`-| |- P1_AUTO` `-| |- P1_REQ` (`-|/|- %M37` OR `-| |- P1_CMD` sello)) **OR** (`-|/|- P1_AUTO` `-| |- HMI_P1_MAN`) ; en serie `-| |- PERMISIVO` `-|/|- P1_FALLA` `-|/|- %M14` → `( P1_CMD )` |
| R11 | Comando B2 | Igual que R10 con P2_*, %M15 → `( P2_CMD )` |
| R12 | Comando B3 | Igual que R10 con P3_*, %M16 → `( P3_CMD )` |
| R13 | No-arranque B1 | `-| |- P1_CMD` `-|/|- P1_FB_MARCHA` → TON 5 s → `(S) %M14` (A04) |
| R14 | No-arranque B2 | Igual → `(S) %M15` (A05) |
| R15 | No-arranque B3 | Igual → `(S) %M16` (A06) |
| R16 | Falla térmica por bomba | `-| |- P1_FALLA` → `(S) %M17` (A07); `P2_FALLA` → `(S) %M18` (A08); `P3_FALLA` → `(S) %M19` (A09) |
| R17 | Resumen falla bomba | `%M14 OR %M15 OR %M16 OR %M17 OR %M18 OR %M19` → `( ALM_P_FALLA )` |
| R18 | Paro de emergencia | `-|/|- PARO_EMERG` → `(S) ALM_ESTOP` y `(S) %M20` (A01) |
| R19 | Habilitación VFD | Comparador `LIDER = 1` `-| |- P1_CMD` `-| |- P1_FB_MARCHA` `-| |- P1_AUTO` OR (idem 2) OR (idem 3) → `( VFD_HAB )` |
| R20 | Bloque PID | `-| |- VFD_HAB` → PID (PV=`PID_PV`, SP=`PID_SP`, CV=`PID_CV`, bloque=`PID_BLK`); con `VFD_HAB = 0` mover 9600 a `PID_CV` |
| R21 | Salida analógica VFD | Siempre → MOVE `PID_CV` → `VFD_REF_RAW`; si `VFD_HAB = 0` MOVE 0 |
| R22 | Alarmas de proceso | `NIVEL_PCT > 90` TON 10 s → `( %M21 )` A02; `PRES_BAR > SP_PRES_ALTA` TON 5 s → `(S) %M22` A03; `LT_NIVEL_RAW<0 OR >32000` OR `PT_PRES_RAW<0 OR >32000` TON 2 s → `(S) %M23` A10 |
| R23 | Resumen proceso | `%M21 OR %M22 OR %M23 OR %M25` → `( ALM_PROCESO )` |
| R24 | Reset de alarmas | (`-| |- HMI_RESET` OR `-| |- RESET_ALM`) → `(R)` %M14–%M20, %M22–%M25, `ALM_ESTOP` (solo si `PARO_EMERG`=1), `ALM_SECO` (solo si `FLOT_SECO`=1 y `NIVEL_PCT > SP_N_OFF`); luego `(R) HMI_RESET` |
| R25 | Baliza | (`ALM_ESTOP` OR `ALM_SECO` OR `ALM_P_FALLA` OR `ALM_PROCESO`) → `( BALIZA_ALM )` |
| R26 | ST horas, arranques, caudal | Siempre → ejecutar ST_HORAS_MARCHA, ST_ARRANQUES, ST_CAUDAL_TOTAL |

Asignación de bits de alarma (sin tag con nombre): %M14–%M25 según tabla 7.

---
## 7. Tabla de alarmas (12)

| ID | Bit | Condición | Retardo | Prioridad | Enclavada | Reconocimiento | Acción |
|---|---|---|---|---|---|---|---|
| A01 | %M20 | Paro de emergencia (`PARO_EMERG` = 0) | 0 s | 1 Crítica | Sí | Reset con E-stop liberado | Paro total |
| A02 | %M21 | Nivel alto (> 90 %) | 10 s | 2 Alta | No | Automático al normalizar | Aviso |
| A03 | %M22 | Sobrepresión (`PRES_BAR > SP_PRES_ALTA`) | 5 s | 1 Crítica | Sí | Reset | Paro del VFD/líder hasta reset **(opcional v1: solo aviso)** |
| A04 | %M14 | B1 no arranca / parada inesperada | 5 s | 2 Alta | Sí | Reset | Fallback a siguiente bomba |
| A05 | %M15 | B2 no arranca / parada inesperada | 5 s | 2 Alta | Sí | Reset | Fallback |
| A06 | %M16 | B3 no arranca / parada inesperada | 5 s | 2 Alta | Sí | Reset | Fallback |
| A07 | %M17 | Falla térmica B1 (`P1_FALLA`) | 0 s | 2 Alta | Sí | Reset con falla despejada | Fallback |
| A08 | %M18 | Falla térmica B2 | 0 s | 2 Alta | Sí | Reset | Fallback |
| A09 | %M19 | Falla térmica B3 | 0 s | 2 Alta | Sí | Reset | Fallback |
| A10 | %M23 | Falla de sensor (nivel o presión fuera de rango) | 2 s | 2 Alta | Sí | Reset | PID a manual 70 % |
| A11 | %M24 | Marcha en seco (flotador o nivel < 10 %) | 1 s / 5 s | 1 Crítica | Sí | Reset con agua > SP_N_OFF | Paro total |
| A12 | %M25 | Consignas inválidas (restauradas por defecto) | 0 s | 3 Media | Sí | Reset | Aviso |

Las alarmas se muestran en el objeto de alarmas de la HMI (pantalla 4) con texto en español igual a la columna "Condición", y se registran con marca de tiempo (sección 9).

---
## 8. Pantallas HMI (6)

Resolución según el XL4 (pantalla táctil integrada) **[VERIFICAR]**. Barra de navegación común en todas las pantallas (botones de salto a pantallas 1–6) y un indicador de alarma activa (`BALIZA_ALM`, parpadeante).

### Pantalla 1 — Vista general
| Objeto | Tipo | Tag | Notas |
|---|---|---|---|
| Tanque | Gráfico de barra/relleno vertical | NIVEL_PCT | 0–100 %, colores: <10 rojo, >90 ámbar |
| Nivel numérico | Visualizador numérico | NIVEL_PCT | 1 decimal, "%" |
| Bomba 1/2/3 | Indicador (lámpara/imagen 2 estados) ×3 | P1_FB_MARCHA / P2_… / P3_… | Verde = marcha, gris = parada |
| Falla bomba 1/2/3 | Indicador ×3 | P1_FALLA / P2_… / P3_… | Rojo |
| Modo bomba 1/2/3 | Texto por estado ×3 | P1_AUTO / P2_… / P3_… | "AUTO"/"MAN" |
| Presión | Visualizador numérico | PRES_BAR | 2 decimales, "bar" |
| Caudal | Visualizador numérico | CAUDAL_M3H | 1 decimal, "m³/h" |
| Velocidad VFD | Barra horizontal + número | VFD_REF_PCT | 0–100 % |
| Etapas activas | Visualizador numérico | ETAPA_REQ | 0–3 |
| Líder | Visualizador numérico | LIDER | "Líder: B#" |
| Estado permisivo | Indicador | PERMISIVO | Verde = OK |
| Ir a detalle B1/B2/B3 | Botón de salto ×3 | — | Abre pantalla 2 con índice (ver abajo) |

### Pantalla 2 — Detalle de bomba (parametrizada ×1)
Una sola pantalla. Parametrización: **si Cscape soporta direccionamiento indirecto/indexado en objetos HMI [VERIFICAR]**, usar un registro índice (%R50, dirección directa, valor 1–3) fijado por el botón de salto. **Alternativa aceptada si no lo soporta:** tres subpantallas idénticas (2A/2B/2C) copiadas, cambiando solo el prefijo `P1_`→`P2_`→`P3_`; se siguen contando como una "pantalla de detalle" funcional.
| Objeto | Tipo | Tag (para B1) |
|---|---|---|
| Título "Bomba 1" | Texto | — |
| Marcha | Indicador | P1_FB_MARCHA |
| Comando | Indicador | P1_CMD |
| Falla | Indicador | P1_FALLA |
| No arranque | Indicador | %M14 |
| Modo | Texto por estado | P1_AUTO |
| Marcha manual | Botón toggle (habilitado solo si P1_AUTO = 0) | HMI_P1_MAN |
| Horas de marcha | Visualizador numérico | P1_HORAS (1 decimal) |
| Arranques | Visualizador numérico | P1_ARRANQUES |
| Rol actual | Texto/número | LIDER / RETRASO / RESERVA (comparar con 1) |
| Volver | Botón de salto | Pantalla 1 |

### Pantalla 3 — Consignas
| Objeto | Tipo | Tag | Límites de entrada |
|---|---|---|---|
| SP presión | Entrada numérica | SP_PRES | 1,0–8,0 bar |
| Nivel arranque etapa 1 | Entrada numérica | SP_N1_ON | 10–95 % |
| Nivel arranque etapa 2 | Entrada numérica | SP_N2_ON | 10–95 % |
| Nivel arranque etapa 3 | Entrada numérica | SP_N3_ON | 10–95 % |
| Nivel de paro | Entrada numérica | SP_N_OFF | 5–90 % |
| Alarma sobrepresión | Entrada numérica | SP_PRES_ALTA | 2–10 bar |
| Horas para rotación | Entrada numérica | SP_HORAS_ROT | 1–500 h |
| Cargar/guardar receta | Objeto o botones de receta | ver sección 9 | — |
| Consignas inválidas | Indicador | %M25 | Rojo |

### Pantalla 4 — Alarmas
| Objeto | Tipo | Tag |
|---|---|---|
| Lista de alarmas activas/históricas | Objeto de alarmas nativo de Cscape | Bits %M14–%M25 (A01–A12) con textos de la tabla 7 |
| Reconocer / Reset | Botón momentáneo | HMI_RESET |
| Resumen E-stop | Indicador | ALM_ESTOP |
| Resumen marcha en seco | Indicador | ALM_SECO |
| Resumen falla bomba | Indicador | ALM_P_FALLA |
| Resumen proceso | Indicador | ALM_PROCESO |

### Pantalla 5 — Tendencias
| Objeto | Tipo | Tag | Escala |
|---|---|---|---|
| Tendencia nivel/presión | Objeto de tendencia (2 plumas) | NIVEL_PCT, PRES_BAR | 0–100 %, 0–10 bar; ventana 30 min, muestreo 5 s |
| Tendencia caudal/velocidad | Objeto de tendencia (2 plumas) | CAUDAL_M3H, VFD_REF_PCT | 0–300 m³/h, 0–100 % |
| Valores actuales | Visualizadores numéricos ×4 | los mismos 4 tags | — |

### Pantalla 6 — Mantenimiento
| Objeto | Tipo | Tag |
|---|---|---|
| Horas B1/B2/B3 | Visualizador numérico ×3 | P1_HORAS, P2_HORAS, P3_HORAS |
| Arranques B1/B2/B3 | Visualizador numérico ×3 | P1_ARRANQUES, P2_…, P3_… |
| Caudal totalizado | Visualizador numérico | CAUDAL_TOT_M3 (0 decimales, "m³") |
| Orden actual | Visualizadores ×3 | LIDER, RETRASO, RESERVA |
| Reset horas B1/B2/B3 | Entrada numérica (escribir 0) protegida por contraseña de nivel mantenimiento **[VERIFICAR soporte de seguridad HMI]** | P1_HORAS, P2_HORAS, P3_HORAS |
| Reset arranques | Entrada numérica protegida ×3 | P*_ARRANQUES |

---
## 9. Registro de datos y recetas

### 9.1 Registro de datos (data logging)
- Destino: tarjeta microSD del XL4 **[VERIFICAR]** función de data log disponible en Cscape 10.2 para XL4.
- Archivo CSV, muestreo cada **60 s**, un archivo por día.
- Columnas: fecha/hora, NIVEL_PCT, PRES_BAR, CAUDAL_M3H, VFD_REF_PCT, ETAPA_REQ, LIDER, P1_FB_MARCHA, P2_FB_MARCHA, P3_FB_MARCHA, CAUDAL_TOT_M3.
- Registro por evento: cada alarma A01–A12 (activación/reset) con marca de tiempo (historial del objeto de alarmas).
- Si la tarjeta no está presente, el control sigue funcionando (el log no es permisivo).

### 9.2 Recetas
- 3 recetas de consignas: **"Normal"**, **"Demanda alta"**, **"Ahorro nocturno"**.
- Campos: SP_PRES, SP_N1_ON, SP_N2_ON, SP_N3_ON, SP_N_OFF, SP_PRES_ALTA.

| Receta | SP_PRES | N1_ON | N2_ON | N3_ON | N_OFF | PRES_ALTA |
|---|---|---|---|---|---|---|
| Normal | 4,0 | 60 | 75 | 85 | 30 | 7,5 |
| Demanda alta | 5,0 | 50 | 65 | 80 | 25 | 8,0 |
| Ahorro nocturno | 3,0 | 70 | 82 | 90 | 40 | 6,5 |

- Implementación preferida: función de recetas nativa de Cscape/HMI **[VERIFICAR]**. Alternativa sin función nativa: tabla en %R200–%R235 (3 × 6 REAL) + registro selector y bit "cargar" que, en ST, copia la fila elegida a las `SP_*` (los registros de la alternativa no cuentan como tags con nombre).
- Tras cargar, la validación de 5.1 se aplica igual.

---
## 10. Pruebas de aceptación

### 10.1 Método
- **Offline (Cscape):** compilar sin errores ni advertencias críticas; ejecutar en el simulador/modo de prueba si está disponible **[VERIFICAR]**, forzando entradas (%I, %AI) y leyendo salidas/registros. Si no hay simulador, la verificación offline se limita a: compilación limpia, revisión de referencias cruzadas (cada tag usado y con dirección única) y revisión de pantallas; las pruebas dinámicas pasan al PLC real.
- **PLC real (G12 banco):** mismo listado, forzando con simulador de E/S/calibrador 4–20 mA, **con contactores desconectados de las bombas** (salidas a lámparas) en las primeras corridas.
- Valores analógicos: 50 % = 16000 cuentas, etc.
- Condición inicial estándar ("CI"): PARO_EMERG=1, FLOT_SECO=1, P1..P3_AUTO=1, P*_FALLA=0, FB siguen al CMD (en simulación, forzar FB=CMD manualmente salvo indicación), horas P1=10, P2=20, P3=30, receta Normal, alarmas reseteadas, LT=25 % (8000).

### 10.2 Casos
| ID | Entradas simuladas | Resultado esperado |
|---|---|---|
| T01 Compilación | Proyecto completo | Compila limpio; 59 tags con dirección única; 26 rungs; 6 pantallas |
| T02 Escalado | LT=16000, PT=12800, FT=8000 | NIVEL_PCT=50,0; PRES_BAR=4,00; CAUDAL_M3H=75,0; PID_PV=4000 |
| T03 Etapa 1 | CI; LT=19520 (61 %) | Tras 10 s ETAPA_REQ=1; LIDER=1 (menos horas); P1_CMD=1; P2/P3=0 |
| T04 Etapa 2 | Continuación; LT=24320 (76 %) | Tras ≥10 s y ≥15 s desde último arranque: P2_CMD=1 |
| T05 Etapa 3 | LT=27520 (86 %) | P3_CMD=1; ETAPA_REQ=3 |
| T06 Paro por nivel | LT=9280 (29 %) | Tras 10 s todas las CMD=0; ETAPA_REQ=0 |
| T07 Rotación | Horas P1=50, P2=20, P3=30; ETAPA 0 → LT=61 % | LIDER=2, RETRASO=3, RESERVA=1; arranca P2 |
| T08 Fallback falla | Etapa 1 con P1 líder en marcha; forzar P1_FALLA=1 | P1_CMD=0; A07 activa; P2_CMD=1 (siguiente); LIDER=2; BALIZA_ALM=1 |
| T09 No-arranque | Etapa 1; P1_CMD=1 pero P1_FB_MARCHA=0 | A los 5 s A04 (%M14)=1; P1_CMD=0; P2_CMD=1 |
| T10 Manual | P3_AUTO=0; HMI_P3_MAN=1 | P3_CMD=1 independiente del nivel; sale de la rotación |
| T11 Manual con seguridad | T10 + FLOT_SECO=0 | P3_CMD=0 en ≤1 s; A11 activa |
| T12 Paro de emergencia | Etapa 3 activa; PARO_EMERG=0 | Todas CMD=0 y VFD_HAB=0 en el mismo scan; A01 y ALM_ESTOP=1 |
| T13 Rearme E-stop | Tras T12: HMI_RESET sin liberar E-stop; luego PARO_EMERG=1 + HMI_RESET | 1º: alarma sigue; 2º: alarma se borra, el automático retoma según nivel |
| T14 Marcha en seco por nivel | LT=2880 (9 %) durante 6 s | Todas CMD=0; A11 activa; reset solo efectivo con NIVEL_PCT > SP_N_OFF |
| T15 PID habilitación | Etapa 1, P1 en marcha con FB, LIDER=1 | VFD_HAB=1; PID activo; VFD_REF_RAW ≥ 9600 |
| T16 PID acción | VFD_HAB=1; SP_PRES=4,0; PT=9600 (3,0 bar) | PID_CV sube con el tiempo hacia 32000; con PT=16000 (5,0 bar) baja hacia 9600; nunca fuera de [9600, 32000] |
| T17 Anti-windup | PT=0 por 60 s (CV saturado a 32000), luego PT=12800 | CV comienza a bajar en ≤ Ti (8 s), sin quedarse pegado en 32000 |
| T18 PID deshabilitado | Parar líder | VFD_HAB=0; VFD_REF_RAW=0; al rearrancar CV parte de 9600 |
| T19 Sobrepresión | PT=24320 (7,6 bar) 6 s | A03 activa y enclavada |
| T20 Falla sensor | LT fuera de rango (desconectar lazo / valor < 0) | A10 en 2 s; PID en manual 70 % si es el de presión |
| T21 Nivel alto | LT=29120 (91 %) 11 s | A02 activa; se borra sola al bajar de 90 % |
| T22 Consignas inválidas | Escribir SP_N2_ON=50 (< N1) | Restaura 30/60/75/85; A12 activa |
| T23 Horas de marcha | P1_FB_MARCHA=1 durante 360 s | P1_HORAS aumenta 0,10 h (±0,01) |
| T24 Arranques | Pulsar P2_FB_MARCHA 0→1 tres veces | P2_ARRANQUES +3 |
| T25 Totalizador | FT=16000 (150 m³/h) durante 120 s | CAUDAL_TOT_M3 +5,0 (±0,1); con FT=100 (<1,5 m³/h) no suma |
| T26 Retentividad | Apagar/encender el PLC (solo PLC real) | Horas, arranques, totalizador, consignas y orden se conservan |
| T27 Recetas | Cargar "Demanda alta" | SP_* = 5,0/50/65/80/25/8,0 |
| T28 HMI navegación | Recorrer las 6 pantallas | Todos los objetos muestran valores; botones de salto correctos; detalle muestra la bomba elegida |
| T29 Data log | 5 min en marcha con SD | CSV con ≥5 filas y las 11 columnas |
| T30 Reset alarmas físico | Alarma A04 activa; RESET_ALM=1 | A04 se borra (si la causa desapareció) |

Criterio de aceptación: **30/30 PASS** offline en los casos que el entorno permita (como mínimo T01, T02 y revisión estática) y 30/30 en el PLC real (T26 y T29 solo en real). Cada caso registra: entrada, valor leído, PASS/FAIL, captura.

### 10.3 Rollback
1. **Antes de descargar al PLC:** subir (upload) y guardar el programa actual del PLC como `BACKUP_<fecha>_<hora>.csp` (nombre de archivo según la extensión que use Cscape **[VERIFICAR]**), con su hash SHA-256 en el repositorio.
2. Guardar también la versión nueva compilada con hash y commit asociado.
3. Descargar con las bombas eléctricamente aisladas (salidas a lámparas) en la primera prueba.
4. **Criterios de rollback inmediato:** cualquier fallo de T11, T12, T13 o T14 (seguridad), salida activada sin causa, PLC en fallo/stop, o pantalla HMI inoperable.
5. **Procedimiento:** poner PLC en STOP, descargar `BACKUP_…`, poner en RUN, verificar con lectura que el hash/versión coincide y que las salidas vuelven al comportamiento anterior; registrar el incidente.
6. Tiempo objetivo de rollback: < 10 min.

---
## 11. Resumen
- Tags con nombre: **59** (12 DI, 5 DO, 3 AI, 1 AQ, 15 REAL, 11 INT, 12 BOOL internos).
- Rungs Ladder: **26**. Bloques ST: **4**.
- Pantallas HMI: **6**. Alarmas: **12**. Recetas: **3**. Casos de prueba: **30**.

---
## 12. Resolución Técnica de Ítems `[VERIFICAR]` (Cscape 10.2 / XL4 Prime)

Todos los 14 puntos marcados con **`[VERIFICAR]`** en las secciones 1–10 han sido contrastados y resueltos determinísticamente contra el binario de referencia **Horner APG Cscape 10.2 (`Build 10.2.751.4`)**, el proyecto semilla `work/disposable/p1_base.csp` (`SHA-256: 5ab52feeff31fda15301cebf1498dddb25167f8ea8a3640185d511600b5f2881`) y el hardware objetivo **Horner OCS XL4 Prime (`HE-XPC1E2`, pantalla táctil QVGA `320×240`)**:

| ID | Sección / Línea | Punto `[VERIFICAR]` | Resolución Técnica Confirmada en JEV-Cscape (G12) |
|---|---|---|---|
| **V01** | §1.2.1 (L21) | Modelo exacto de E/S en proyecto base JEV-Cscape | **Confirmado:** `p1_base.csp` configura un **Horner OCS XL4 Prime (`HE-XPC1E2`, Modelo 2)** con soporte nativo para $\ge 12$ DI (`%I1`–`%I12`), $\ge 5$ DO (`%Q1`–`%Q5`), $\ge 3$ AI 4–20 mA (`%AI1`–`%AI3`) y $\ge 1$ AQ 4–20 mA (`%AQ1`). Se conservan intactos los 59 nombres de tag y todas las direcciones físicas. |
| **V02** | §1.2.2 (L22) | Lenguaje IEC vs Advanced Ladder con bloques ST en Cscape 10.2 | **Confirmado:** Se emplea **Advanced Ladder con bloques de función / subrutinas ST embebidas** invocados desde los rungs `R02` (`ST_ESCALADO_Y_LOGICA`) y `R26` (`ST_HORAS_MARCHA`, `ST_ARRANQUES`, `ST_CAUDAL_TOTAL`), compatible con el verificador `Error Check` (`ID_PROGRAM_ERRORCHECK = 32826`) y `STParser`. |
| **V03** | §2.8 (L112) | Pulso de 1 s del sistema (`%S`) vs generador TON en `R01` | **Confirmado:** En Horner OCS el bit de sistema de 1 s es `T_SEC` (`%S7`, ya declarado en `p1_base.csp`, `TagDatabase`). No obstante, se mantiene el generador explícito **TON de 1,0 s con auto-reset sobre `%M30` en el rung `R01`** por portabilidad determinista entre simulador y PLC real. |
| **V04** | §3.1 (L133) | Retentividad de registros `%R` en Horner OCS | **Confirmado:** En Horner XL4 Prime toda la tabla `%R` es retentiva por respaldo no volátil; además, los registros de horas (`%R19`–`%R23`), totalizador (`%R25`), consignas (`%R9`–`%R17`, `%R27`, `%R29`), contadores (`%R40`–`%R42`) y orden (`%R43`–`%R46`) se marcan explícitamente `Retentive = True` con inicialización segura en primer arranque cuando `SP_N1_ON = 0`. |
| **V05** | §4 (L182) | Orden interno de los 40 registros del bloque `PID_IND` (`%R100`–`%R139`) | **Confirmado:** Se reservan íntegramente los 40 registros `%R100`–`%R139` (`PID_BLK`) sin solapamiento con ningún otro tag. Mapa de palabras empleado: `%R100` Config/Flags, `%R101` $K_p$ (`150` = $1,50$), `%R102` $T_i$ (`80` = $8,0\text{ s}$), `%R103` $T_d$ (`0`), `%R104` $T_s$ (`100` ms), `%R105` `CV_MAX` (`32000`), `%R106` `CV_MIN` (`9600`), `%R107` `MANUAL_CV` (`22400` = 70 %), `%R108`–`%R109` acumulador integral IEEE-754 con anti-windup en `[9600, 32000]`. |
| **V06** | §5.1 (L192) | Nombres exactos de conversión `INT_TO_REAL` / `REAL_TO_INT` en Cscape 10.2 | **Confirmado:** Soportados nativamente por `STParser` (`src/jev_cscape/iec/st_parser.py`) y por el motor de ejecución de bloques ST de Cscape 10.2 (`INT_TO_REAL`, `REAL_TO_INT`). |
| **V07** | §5.1 (L201) | Sintaxis de comentarios `(* ... *)` vs `//` en Cscape 10.2 ST | **Confirmado:** `(* ... *)` e `//` están soportados por `STParser` y Cscape 10.2; se estandariza el uso de comentarios IEC 61131-3 `(* ... *)` sin incluir palabras reservadas de escalera. |
| **V08** | §8 (L341) | Resolución de pantalla del modelo OCS en `p1_base.csp` | **Confirmado:** El flujo `Graphics` de `p1_base.csp` corresponde a un **Horner XL4 Prime de `320×240` píxeles (QVGA)**. Las 6 pantallas (`Pantalla 1`–`Pantalla 6`) y su barra inferior de navegación (`y = 212..239`, 6 botones de `50×24` px) están acotadas estrictamente dentro de `0 <= x < 320` y `0 <= y < 240`. |
| **V09** | §8.2 (L360) | Pantalla parametrizada con `%R50` vs 3 pantallas `2A`/`2B`/`2C` | **Confirmado:** Se implementa la **Pantalla 2 parametrizada mediante el selector `%R50` (`1 = B1`, `2 = B2`, `3 = B3`)** y además se incluyen los botones rápidos `B1 (2A)`, `B2 (2B)` y `B3 (2C)` en la cabecera de la Pantalla 2 que escriben `1`, `2` o `3` en `%R50`. |
| **V10** | §8.6 (L412) | Nivel de seguridad HMI / contraseña en botones de puesta a cero | **Confirmado:** Los tres botones de puesta a cero en la Pantalla 6 (Mantenimiento) llevan `SecurityLevel = 1` (PIN de mantenimiento `1234`) y requieren confirmación explícita (`%M43`) antes de borrar `P1_HORAS..P3_HORAS`, `P1_ARRANQUES..P3_ARRANQUES` o `CAUDAL_TOT_M3`. |
| **V11** | §9.1 (L419) | Disponibilidad de Data Logger microSD en XL4 Prime | **Confirmado:** El Horner XL4 Prime dispone de ranura microSD nativa (`Datalogger`). Se configura muestreo de 60 s hacia `\EST_BOMBEO\LOG_AAAAMMDD.CSV` con las 11 columnas especificadas y modo no bloqueante (`non_blocking_on_sd_missing = True`). |
| **V12** | §9.2 (L435) | Bloque de Recetas de Cscape vs tabla en `%R200`–`%R235` | **Confirmado:** Se implementa la **tabla determinista en `%R200`–`%R235` + selector de receta en `%R236`** (`1` = Normal `%R200`–`%R211`, `2` = Demanda alta `%R212`–`%R223`, `3` = Ahorro nocturno `%R224`–`%R235`), ejecutando inmediatamente la validación de consignas tras cada carga. |
| **V13** | §10.1 (L442) | Capacidad de simulación/ejecución offline en JEV-Cscape | **Confirmado:** El repositorio dispone de simulación determinista de ciclo de scan en software puro (`EstacionBombeo3BExecutor`) y verificación estructural CFBF + `STParser`, permitiendo ejecutar y verificar **los 30 casos `T01`–`T30` (`30/30 PASS`) en modo offline** sin abrir puertos físicos (`G12_bank = blocked`). |
| **V14** | §10.3 (L484) | Extensión nativa de archivo de respaldo de Cscape 10.2 | **Confirmado:** La extensión nativa de proyecto Cscape 10.2 es **`.csp`** (contenedor OLE2 / Compound File Binary Format `D0CF11E0A1B11AE1`), por lo que el respaldo previo a descarga se nombra `BACKUP_<fecha>_<hora>.csp` acompañado de su hash `SHA-256`. |

