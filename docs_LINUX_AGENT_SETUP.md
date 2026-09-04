# Linux Endpoint Agent — o'rnatish yo'riqnomasi

Windows Agent bilan bir xil yadrodan (`agent_core/`) foydalanadi -
farqi faqat kuzatiladigan papkalar (`~/Downloads`, `~/Desktop`, `/tmp`,
`/var/tmp`) va ishga tushirish usuli (systemd, Windows Service o'rniga).

## 1. Fayllarni nusxalash

```bash
sudo mkdir -p /opt/network-security-agent
sudo cp -r agent_core windows_agent linux_agent config db /opt/network-security-agent/
sudo cp requirements-agent.txt /opt/network-security-agent/
```

## 2. Kutubxonalarni o'rnatish

```bash
cd /opt/network-security-agent
pip install -r requirements-agent.txt --break-system-packages
```

## 3. Sozlash

```bash
sudo tee /opt/network-security-agent/.env << EOF
API_SERVER_URL=https://172.16.0.5:8443
AGENT_API_KEY=<markazdagi bilan bir xil kalit>
AGENT_CA_BUNDLE_FILE=/opt/network-security-agent/ca.crt
AGENT_LOG_FILE=/var/log/network-security-agent-app.log
AGENT_CACHE_FILE=/opt/network-security-agent/agent_hash_cache.json
EOF
```

**MUHIM (xavfsizlik auditi, CRITICAL)**: server endi `nginx` orqali
haqiqiy TLS bilan ishlaydi (`docs_TLS_SETUP.md`ga qarang) - shuning
uchun `https://` ishlatiladi. `AGENT_CA_BUNDLE_FILE` ichki CA
(`deploy/pki/certs/ca.crt`) nusxasiga ishora qilishi kerak - aks
holda so'rov ishonchsiz sertifikat sababli rad etiladi.

## 4. systemd xizmati sifatida o'rnatish

```bash
sudo cp linux_agent/endpoint-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now endpoint-agent
```

## 5. Tekshirish

```bash
sudo systemctl status endpoint-agent
sudo journalctl -u endpoint-agent -f
```

## Nima uchun `User=root` kerak

`process_killer.py` boshqa foydalanuvchi jarayonini to'xtatishi kerak
bo'lishi mumkin (masalan umumiy serverda boshqa xodim yuklab olgan
faylni ochgan jarayon). Agar faqat bitta foydalanuvchi kompyuteri
bo'lsa (masalan ish stantsiyasi), `User=<foydalanuvchi-nomi>` qilib
cheklash mumkin - lekin bu holda faqat shu foydalanuvchining o'z
jarayonlarini to'xtata oladi.

## Ko'p-distributiv moslik

`agent_core/file_monitor.py` (`watchdog`) va `agent_core/process_killer.py`
(`psutil`) - ikkalasi ham distributivdan mustaqil (Ubuntu, RHEL/Rocky
Linux, Debian - hammasida bir xil ishlaydi, chunki Python kutubxonalari
orqali ishlaydi, distributiv-specific vositalarga bog'liq emas).
