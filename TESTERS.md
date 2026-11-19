# ARMax testnet — tester guide / Guía para testers

**ES** · [English below](#english)

> ARMax es una red de **pruebas**. Los coins de la testnet **no tienen valor**, la red puede reiniciarse sin aviso
> y el software **no ha sido auditado**. No uses en ella una frase de respaldo que uses en otro lado.

## Qué necesitas
* Teléfono **Android 8+ de 64 bits (arm64)**. Recomendado: 4 GB de RAM o más (cada hilo de minado usa ~384 MiB).
* Datos móviles o Wi-Fi, y paciencia: con un solo teléfono un bloque tarda ~5 minutos.
* No es necesario configurar nada de red: la app trae el nodo semilla del proyecto.

## Instalar
1. Descarga el APK: **https://github.com/DevARM64/armax-core/releases/download/v0.1.4-testnet/ARMax-testnet-0.1.4.apk** (compara el SHA-256 con el publicado: `0433F4E0EFCC3AC4477DD8C55F951201C83E50D7DD14A9107370309BCB4BFEB1`).
2. Ábrelo y acepta "instalar apps de origen desconocido" para tu navegador o gestor de archivos.
3. Abre ARMax y permite las notificaciones. El chip superior debe decir **TESTNET**.
4. Al crear la cartera, **anota la frase de respaldo en papel**. No la compartas ni la publiques.

## Probar
1. En el Panel espera a que aparezca **Sincronizado** y **pares 1/1** (la primera vez puede tardar unos minutos).
2. Pulsa **Iniciar nodo** y activa el minado. Si lo dejas minando, en Ajustes puedes elegir si minar solo con la pantalla
   encendida o sin cargador. Ten en cuenta calor y batería.
3. Comprueba que ves H/s, bloques y shares. Tu saldo aparece en **Madurando** y pasa a **Gastable** tras 100 bloques (~8 h).
4. **Recibir:** muestra tu dirección/QR. **Enviar:** pega o escanea una dirección (cámara) y envía una cantidad pequeña.
5. Cierra y abre la app, y reinicia el teléfono: ¿sigue sincronizando y minando?

## Qué reportar
Modelo y versión de Android, versión de la app, qué hiciste, qué esperabas y qué pasó, y una captura si puedes.
Nos interesa especialmente: no sincroniza, se cierra, se calienta o gasta mucha batería, H/s muy bajos, envíos que no llegan.

* Errores y dudas: en el grupo de testers.
* **Fallos de seguridad:** de forma privada, ver `SECURITY.md` (pestaña *Security* del repositorio). No los publiques.

---

## English

> ARMax is a **test** network. Testnet coins have **no value**, the network may be reset without notice, and the
> software is **unaudited**. Do not use a recovery phrase that you use anywhere else.

### Requirements
* **64-bit (arm64) Android 8+** phone. 4 GB RAM or more recommended (each mining thread uses ~384 MiB).
* Mobile data or Wi-Fi, and patience: with a single phone a block takes ~5 minutes.
* No network setup needed: the app ships with the project's seed node.

### Install
1. Download the APK: **https://github.com/DevARM64/armax-core/releases/download/v0.1.4-testnet/ARMax-testnet-0.1.4.apk** (compare its SHA-256 with the published one: `0433F4E0EFCC3AC4477DD8C55F951201C83E50D7DD14A9107370309BCB4BFEB1`).
2. Open it and allow "install unknown apps" for your browser or file manager.
3. Open ARMax and allow notifications. The top chip must read **TESTNET**.
4. When the wallet is created, **write the recovery phrase on paper**. Do not share or post it.

### Test
1. On the Dashboard wait for **Synced** and **peers 1/1** (the first time it can take a few minutes).
2. Start the node and enable mining. In Settings you can choose to mine only with the screen on or without a charger.
   Watch heat and battery.
3. Check that you see H/s, blocks and shares. Your balance shows as **Maturing** and becomes **Spendable** after 100 blocks (~8 h).
4. **Receive:** show your address/QR. **Send:** paste or scan an address (camera) and send a small amount.
5. Close and reopen the app, and reboot the phone: does it keep syncing and mining?

### What to report
Phone model and Android version, app version, what you did, what you expected, what happened, and a screenshot if possible.
Especially: won't sync, crashes, overheating or heavy battery use, very low H/s, sends that never arrive.

* Bugs and questions: in the testers group.
* **Security issues:** privately, see `SECURITY.md` (the repository's *Security* tab). Do not post them publicly.
