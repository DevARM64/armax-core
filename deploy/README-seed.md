# Nodo semilla público de ARMax

Un VPS con IP pública que acepta conexiones entrantes (`--listen`) y retransmite bloques y shares.
No mina: los teléfonos se conectan a él y así funcionan con datos móviles y fuera del Wi-Fi.

1. VPS Ubuntu 22.04/24.04, 1 vCPU, 1–2 GB RAM, ~10 GB disco, IP pública. Abre el puerto **TCP 8333**
   en el firewall del proveedor (además de `ufw`, que el script abre).
2. Sube el repo (`git clone` o `scp` del tar) e instala Rust con rustup.
3. `sudo bash deploy/install-seed.sh` (compila, instala el servicio `armax-seed` y lo arranca).
4. Copia la **clave pública** que imprime (también en `journalctl -u armax-seed`).
5. En la app: *Ajustes → Conectar a* `IP_DEL_VPS:8333` y *Clave fijada* `IP_DEL_VPS:8333=CLAVE`.
   Para que venga de fábrica, ponlo en `armax-android/app/src/main/res/values/seeds.xml`.
6. Copia de seguridad: `/var/lib/armax/node.key` (si se pierde, la clave cambia y todos tendrán que
   actualizar la clave fijada).

Notas: en x86 la VM usa el respaldo portable (más lento que NEON) pero un nodo que solo valida la red
`fast` lo soporta. Para la red `devnet` (384 MiB por verificación) hace falta más RAM.
