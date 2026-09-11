# Alzubairy Remote License Service

خدمة مستقلة لإدارة تراخيص Alzubairy Remote. الاستخدام الشخصي مجاني حتى ثلاثة أجهزة، بينما تفتح خطط Business خصائص الإدارة المركزية.

## التشغيل

```bash
cp .env.example .env
# غيّر كلمة المرور والرابط العام داخل .env
docker compose up -d --build
```

يشغّل Compose بوابة Caddy ويصدر شهادة HTTPS تلقائيًا للنطاق `license.fzremote.net`. لوحة الإدارة في `/admin` وواجهة فحص الصحة في `/health`.

احتفظ بنسخة احتياطية من مجلد `data`. يحتوي ملف `license_signing_ed25519.pem` على مفتاح التوقيع الخاص ويجب ألا يُرفع إلى Git أو يُشارك مع أي شخص.
