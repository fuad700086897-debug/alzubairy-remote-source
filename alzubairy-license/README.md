# Alzubairy Remote License Service

خدمة مستقلة لإدارة تراخيص Alzubairy Remote. الاستخدام الشخصي مجاني حتى ثلاثة أجهزة، بينما تفتح خطط Business خصائص الإدارة المركزية.

## التشغيل

```bash
cp .env.example .env
# غيّر كلمة المرور والرابط العام داخل .env
docker compose up -d --build
```

الخدمة تستمع محليًا على `127.0.0.1:8080` ويجب نشرها خلف HTTPS عبر Caddy أو Nginx. لوحة الإدارة في `/admin` وواجهة فحص الصحة في `/health`.

احتفظ بنسخة احتياطية من مجلد `data`. يحتوي ملف `license_signing_ed25519.pem` على مفتاح التوقيع الخاص ويجب ألا يُرفع إلى Git أو يُشارك مع أي شخص.

