# NexoMesh Multiplataforma (Android APK + Windows/Linux/macOS + iOS)

Proyecto completo P2P con WireGuard, cifrado Noise IKpsk2, perforación STUN NAT, reconexión exponencial y exportación CSV.

## Configuración detectada
- IP Virtual TUN: `10.0.0.1/24`
- MTU: `1280`
- Keepalive STUN: `10s`
- Servidor STUN: `stun.l.google.com:19302`

## 1. Android APK (GitHub Actions o Android Studio)
1. Sube todo el contenido de este `.zip` (incluyendo `.github/workflows/`) a un repositorio en GitHub.
2. En **Actions → Compilar NexoMesh APK**, descarga el artefacto **`nexomesh-vpn-debug-apk`** e instala el `.apk` en tu celular.
3. Localmente: dentro de `rust-core/` ejecuta `cargo ndk -t arm64-v8a -o ../app/src/main/jniLibs build --release` y abre el proyecto en Android Studio.

## 2. Escritorio Windows, Linux y macOS (`desktop-cli/`)
- En **Actions → Compilar NexoMesh Desktop**, descarga los ejecutables compilados para **Windows (`.exe`)**, **Linux** y **macOS**.
- O compila localmente con Rust:
  ```bash
  cd desktop-cli
  cargo run --release -- --mode auto --stun stun.l.google.com:19302 --export-wg-conf nexomesh-wg.conf
  ```
- También puedes unir tu PC directamente al QR de tu celular:
  ```bash
  cargo run --release -- --join "nexomesh://join?..."
  ```

## 3. iPhone / iPad (iOS) (`apple-ios/`)
- Incluye `apple-ios/NexoMeshPacketTunnel.swift` (plantilla `NEPacketTunnelProvider` para Xcode) y `apple-ios/NexoMesh-WireGuard-Template.conf` para importar en la app WireGuard de iOS o macOS.
