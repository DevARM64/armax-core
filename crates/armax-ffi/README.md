# armax-ffi — puente Android

Biblioteca C (`libarmax_ffi.so`) con el nodo, la minería y la cartera de ARMax. Cabecera: `include/armax.h`.

## Compilar para Android (en una máquina con Android NDK y red)
```
rustup target add aarch64-linux-android
export ANDROID_NDK_HOME=...
cargo build --release -p armax-ffi --target aarch64-linux-android \
  --config target.aarch64-linux-android.linker=\"$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android24-clang\"
# copiar target/aarch64-linux-android/release/libarmax_ffi.so a app/src/main/jniLibs/arm64-v8a/
```
(También se puede compilar directamente en Termux: `cargo build --release -p armax-ffi` y usar el `.so` de `target/release/`.)

## Flujo de la app
1. Primera vez: `armax_wallet_create` → mostrar la frase de 12 palabras UNA vez; guardar el sellado en `filesDir/wallet.sealed`.
2. Cada arranque: `armax_node_start(config, vault, sealed)`; después, un hilo llama a `armax_node_push_sensors` cada ~5 s.
   Sin sensores el gobernador no mina (falla seguro).
3. UI: `armax_node_status` (JSON) cada segundo; `armax_node_send` para pagar.
4. Parar: `armax_node_stop` (una sola vez).

`android/*.kt` son bocetos **sin compilar ni probar**; la parte Rust sí tiene pruebas (`tests/ffi.rs`), que llaman a la ABI con una bóveda simulada.

## Límites conocidos
- La app debe ser un servicio en primer plano; Android puede matarlo.
- Los montos del JSON van como cadenas en unidades (1 ARM = 100000000).
- La cartera usa una sola dirección (`m/…/0'/0'/0'`); la transacción de cambio vuelve a ella.

## Historial
`armax_node_history(handle, limit, out, cap)` escribe un arreglo JSON (lo más reciente primero, pendientes antes) con `kind` (`mined|received|sent|internal`), `amount` (unidades, cadena), `height`/`timestamp` (null si está pendiente), `txid`, `counterparty`, `confirmations`, `matures_in` y `fee` (comisión en unidades como cadena; solo en envíos hechos desde este nodo, si no `null`). Necesita ≈ 350 bytes por entrada.
