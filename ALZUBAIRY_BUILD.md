# Alzubairy Remote build profile

Alzubairy Remote (الزبيري) is based on the AGPL-3.0 RustDesk client.

## Product targets

- Windows 10/11 x64 installer.
- Android APK.
- Arabic-first interface with English fallback.
- Self-hosted rendezvous and relay servers.
- Visible session indication and explicit consent by default.

## Release gates

1. Test Windows screen, input, audio, clipboard, and file transfer.
2. Test the Android controller on a physical device.
3. Keep unattended access disabled by default.
4. Pin the production server public key.
5. Sign release builds before public distribution.
