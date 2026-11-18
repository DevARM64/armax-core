# ARMax para Android (versión de desarrollo)

App mínima: crea o restaura una cartera (frase de 12 palabras, sellada con el Android Keystore),
corre el nodo y el minero en un servicio en primer plano (con el gobernador térmico), muestra el
estado y permite **recibir** y **enviar** ARM, con un **historial** de movimientos (minado, recibido, enviado). Usa el núcleo Rust (`crates/armax-ffi`) por JNA.

> **Estado:** el código Kotlin está revisado a mano y su parte no visual se comprobó con un
> compilador de Kotlin, pero **este proyecto no se ha compilado ni ejecutado nunca en Android**
> (en el entorno donde se escribió no hay Android SDK ni red). Es normal que haya que arreglar
> algún detalle en la primera compilación: manda la captura del error de la pestaña *Build*.
> Es una versión de desarrollo: **no guardes fondos reales**.

## Qué necesitas (en el computador)
1. **Android Studio** (Koala o más nuevo) con *SDK Platform 34* y, en *SDK Manager → SDK Tools*,
   **NDK (Side by side)** y *Android SDK Command-line Tools*.
2. **Rust** (https://rustup.rs) y el objetivo de Android + `cargo-ndk`:
   ```
   rustup target add aarch64-linux-android
   cargo install cargo-ndk
   ```
3. Un teléfono **ARM de 64 bits** (el A; el B, de 32 bits, no sirve) con *depuración USB* activada.

## 1. Compilar la biblioteca del nodo (`libarmax_ffi.so`)
Desde la carpeta `armax-core` (la que contiene `Cargo.toml` y `crates/`):

Linux / macOS:
```
export ANDROID_NDK_HOME=$HOME/Android/Sdk/ndk/<versión>      # macOS: $HOME/Library/Android/sdk/ndk/<versión>
cargo ndk -t arm64-v8a -o armax-android/app/src/main/jniLibs build --release -p armax-ffi
```
Windows (PowerShell):
```
$env:ANDROID_NDK_HOME = "$env:LOCALAPPDATA\Android\Sdk\ndk\<versión>"
cargo ndk -t arm64-v8a -o armax-android/app/src/main/jniLibs build --release -p armax-ffi
```
Debe quedar `armax-android/app/src/main/jniLibs/arm64-v8a/libarmax_ffi.so`. Sin ese archivo la app
se cierra al abrirse.

## 2. Compilar y abrir la app
1. En Android Studio: *Open* → carpeta `armax-android`. Espera a que termine *Gradle Sync*
   (descarga dependencias: necesita internet la primera vez).
2. Conecta el teléfono por USB y pulsa **Run ▶**.

## 3. Primera prueba con tus nodos de Termux (red `fast`)
La app del teléfono A hará de nodo nuevo y se sincronizará con el nodo de Termux del teléfono B:

1. En B (Termux), con la red de pruebas de siempre, arranca el nodo **escuchando** (carpeta de datos
   que ya tiene la cadena):
   ```
   ./target/release/armax-node run --network fast --data ~/poolB --wallet ~/pool.wallet --listen 0.0.0.0:8333 --mine --pool --any-power --no-temp
   ```
   Anota la línea `clave pública del nodo: …` y la IP de B (en Termux: `ifconfig` o *Ajustes → Wi-Fi*).
2. En A **detén** el nodo de Termux (`quit`) para no competir por la batería.
3. Abre la app en A → *Crear cartera nueva* → anota las 12 palabras → *Continuar*.
4. *Ajustes*: deja **Red de pruebas rápida** activada, pon en *Conectar a* `IP_DE_B:8333` y en
   *Clave fijada* `IP_DE_B:8333=CLAVE_DE_B`. Activa *Minar con la pantalla encendida* (si no, el
   gobernador pausa mientras miras la app) y, si A no está enchufado, *Minar también sin cargador*.
   *Guardar*.
5. *Estado* → *Iniciar nodo*. Acepta el permiso de notificaciones. Debes ver `Pares 1/1`, la altura
   subiendo hasta la de B y, en *Minero*, `minando` o `limitado por temperatura`.
6. *Recibir* → *Copiar dirección*; envíala desde B con `send DIRECCIÓN 2`. Cuando se confirme
   (bloques nuevos) aparece en *Saldo*. *Enviar* hace el camino inverso.

## Historial
La pestaña **Historial** lista lo minado (coinbase y shares del pool), lo recibido y lo enviado por tu
dirección, lo pendiente primero. Se calcula recorriendo la cadena principal desde la punta (no se
guarda aparte) y se actualiza cada 5 s mientras la pestaña está abierta. Un envío muestra lo que fue
a otras direcciones, sin el cambio que vuelve a ti, y no incluye la comisión. Lo minado indica en
cuántos bloques madura. Se muestran los 100 movimientos más recientes.
La **comisión** de un envío se muestra si el envío se hizo desde este nodo: se anota en `sent.log`
(dentro de la carpeta de datos). Un envío hecho desde otro dispositivo con la misma cartera no la muestra.

## Código QR
La pestaña **Recibir** muestra el QR de tu dirección (librería ZXing `core`, solo el generador; la
primera sincronización de Gradle la descarga de internet). Escanear QR con la cámara aún no está hecho.

## Idiomas, aspecto y logos
* **Inglés y español.** Los textos están en `res/values/strings.xml` (inglés, por defecto) y
  `res/values-es/strings.xml`. La app sigue el idioma del teléfono; en Android 13+ *Ajustes → Idioma*
  abre el selector de idioma por app. Para añadir otro idioma: copia `strings.xml` a `values-XX/`,
  tradúcelo y añade `XX` a `res/xml/locales_config.xml`. Los errores del núcleo Rust están en español;
  solo los conocidos se traducen (`Armax.localizeNative`).
* **Tema.** Oscuro por defecto con acento cian (el del logo) y verde para lo correcto; el ámbar queda para avisos y temperatura (`warningColor()`); también hay variante clara
  y sigue al sistema. Colores en `Theme.kt`.
* **Logo.** Ya lleva el logo oficial (la "A" azul). Para cambiarlo: `res/drawable-nodpi/ic_logo.png`
  (dentro de la app, cuadrado con fondo transparente), `res/drawable-nodpi/ic_launcher_foreground.png`
  (ícono del lanzador, 432×432 con el logo en el centro, ocupando ~50 %; el fondo es el color
  `ic_launcher_background` de `res/values/colors.xml`) y `res/drawable/ic_stat_armax.xml` (silueta
  monocroma de la notificación).

## Nodos públicos
Para minar con datos móviles hace falta un nodo con IP pública: ver `deploy/README-seed.md` (script y
servicio systemd). Sus datos de fábrica van en `res/values/seeds.xml` (`default_connect`, `default_pin`).

## Notas de diseño
* **Frase de respaldo:** se muestra una sola vez y solo se guarda la cartera *sellada* (AES-GCM con
  una clave del Keystore que no sale del teléfono). La cartera no se incluye en copias de seguridad
  de Android (`allowBackup=false`): si cambias de teléfono, restaura con las 12 palabras.
* **Servicio en primer plano:** Android exige la notificación fija. Mientras el nodo corre, la app
  mantiene el procesador despierto (WakeLock parcial) para no perder a los pares con la pantalla
  apagada. El botón *Detener* de la notificación o de la app lo apaga y libera todo.
* **Gobernador térmico:** pausa por temperatura, batería (mínimo configurable), memoria, falta de
  cargador (salvo *Minar también sin cargador*) y pantalla encendida (salvo el ajuste).
* **Red `devnet`:** usa los parámetros de consenso (384 MiB por hilo, ~5 H/s). Aún no hay nodos
  públicos: úsala solo para pruebas de rendimiento.
* **Solo `arm64-v8a`.** Para 32 bits habría que añadir `armv7-linux-androideabi` y su ABI.

## APK firmada (release)

1. Crea el keystore una sola vez (ver abajo) y haz copia de seguridad en dos sitios.
2. Copia `keystore.properties.example` a `keystore.properties` y pon tus datos.
3. `gradlew assembleRelease` (o Build → Generate Signed App Bundle / APK).
   Resultado: `app/build/outputs/apk/release/app-release.apk`.
4. Para cada versión nueva sube `versionCode` (entero, siempre mayor) y `versionName` en `app/build.gradle.kts`.

Crear el keystore (JDK de Android Studio):
`keytool -genkeypair -v -keystore armax-release.jks -alias armax -keyalg RSA -keysize 4096 -validity 36500`

Si pierdes el keystore o su contraseña NO podrás publicar actualizaciones de la misma app.

## Escanear QR (Enviar)

El botón "Escanear QR" de la pestaña Enviar abre la cámara (zxing-android-embedded) y rellena la dirección.
Acepta la dirección sola o con prefijo `armax:` y parámetros. El permiso de cámara se pide solo al usar el botón;
la app funciona igual sin ella (la cámara es opcional en el manifiesto).
