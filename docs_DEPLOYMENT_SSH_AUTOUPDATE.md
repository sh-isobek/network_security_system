# SSH orqali GitHub'dan Avtomatik Deploy (Auto-Update)

Bu hujjat production serveringizni (masalan sizning
`network1411tas-Virtual-Machine`) GitHub'ga **SSH orqali** ulab,
`main` branch'ga yangi commit tushganda **avtomatik ravishda**
yangilanadigan qilib sozlashni tushuntiradi.

## 1. SSH Deploy Key yaratish (serverda)

**Muhim**: shaxsiy SSH kalitingizni ishlatmang - repo uchun alohida,
**faqat o'qish huquqiga ega** (read-only) "deploy key" yarating. Bu
xavfsizroq - agar server buzilsa, tajovuzkor faqat shu bitta repo'ni
o'qiy oladi, boshqa hech narsaga yozib ham, boshqa repo'larga kira
ham olmaydi.

```bash
sudo mkdir -p /opt/network_security_system
sudo ssh-keygen -t ed25519 -f /root/.ssh/network_security_deploy_key -N "" -C "network-security-deploy@$(hostname)"
sudo cat /root/.ssh/network_security_deploy_key.pub
```

Chiqargan ochiq kalitni nusxalang.

## 2. Deploy Key'ni GitHub'ga qo'shish

1. `https://github.com/sh-isobek/network_security_system/settings/keys` sahifasiga o'ting
2. **"Add deploy key"** tugmasini bosing
3. Title: masalan `production-server`
4. Key: yuqoridagi ochiq kalitni joylashtiring
5. **"Allow write access"ni BELGILAMANG** (faqat o'qish kifoya - deploy kalitiga yozish huquqi berish xavfsizlik xatari)
6. **"Add key"** ni bosing

## 3. SSH konfiguratsiyasi (serverda)

```bash
sudo tee -a /root/.ssh/config << 'EOF'
Host github.com-network-security
    HostName github.com
    User git
    IdentityFile /root/.ssh/network_security_deploy_key
    IdentitiesOnly yes
EOF
sudo chmod 600 /root/.ssh/config
```

GitHub'ning host kalitini ishonchli manbalarga qo'shish (birinchi
ulanishda "host authenticity" so'rovini oldini olish uchun):
```bash
sudo ssh-keyscan github.com >> /root/.ssh/known_hosts
```

## 4. Repo'ni klonlash

```bash
sudo git clone git@github.com-network-security:sh-isobek/network_security_system.git /opt/network_security_system
cd /opt/network_security_system
sudo cp .env.example .env
sudo nano .env   # POSTGRES_PASSWORD, AGENT_API_KEY va boshqa maxfiy qiymatlarni to'ldiring
```

## 5. Birinchi marta qo'lda ishga tushirish

```bash
cd /opt/network_security_system
sudo docker compose up -d
sudo docker compose exec dashboard python -m dashboard.create_user --username admin --password 'KuchliParol!' --role admin
```

## 6. Avtomatik yangilanishni sozlash (systemd timer)

```bash
sudo cp deploy/network-security-deploy.service /etc/systemd/system/
sudo cp deploy/network-security-deploy.timer /etc/systemd/system/

sudo systemctl daemon-reload
sudo systemctl enable --now network-security-deploy.timer

# Holatni tekshirish:
sudo systemctl status network-security-deploy.timer
sudo systemctl list-timers network-security-deploy.timer
```

Bundan buyon **har 5 daqiqada** (`.timer` faylidagi `OnUnitActiveSec`
orqali sozlanadi) tizim GitHub'ni tekshiradi:
- Yangi commit **yo'q** bo'lsa - hech narsa qilinmaydi (jim)
- Yangi commit **bor** bo'lsa: avtomatik backup oladi -> `git pull`
  qiladi -> Docker image'larni qayta quradi -> xizmatlarni qayta
  ishga tushiradi -> health-check qiladi

## Qo'lda ishga tushirish (test uchun)

```bash
sudo systemctl start network-security-deploy.service
sudo journalctl -u network-security-deploy.service -f
# yoki to'g'ridan-to'g'ri:
sudo tail -f /var/log/network_security_deploy.log
```

## Muhim: xavfsizlik va ishonchlilik

- **Deploy log'ini muntazam kuzatib turing** (`/var/log/network_security_deploy.log`)
  - health-check muvaffaqiyatsiz bo'lsa, deploy skripti xato kodi
    bilan chiqadi va `journalctl`/systemd'da ko'rinadi
- **Deploy'dan oldin avtomatik backup olinadi** - agar yangi versiya
  muammoli bo'lsa, `docs/DISASTER_RECOVERY_GUIDE.md`dagi tartib
  bo'yicha oldingi holatga tiklashingiz mumkin
- **Bir vaqtda bir nechta deploy jarayoni** ishga tushib qolmasligi
  uchun skript `flock` orqali himoyalangan (real test qilingan)
- Agar avtomatik yangilanishni **vaqtincha to'xtatish** kerak bo'lsa:
  ```bash
  sudo systemctl stop network-security-deploy.timer
  ```

## Test holati

`deploy/auto_deploy.sh`ning asosiy mantig'i (yangi commit aniqlash,
o'zgarish-yo'q holat, backup+pull+deploy zanjiri, health-check
muvaffaqiyat/muvaffaqiyatsizlik, bir vaqtda ikkita jarayonning oldini
olish) **haqiqiy ikkita git repo** (GitHub va production server
o'rnini bosuvchi) bilan to'liq test qilingan. `systemd` unit fayllari
haqiqiy `systemd-analyze verify` orqali tasdiqlangan. Docker Compose
buyruqlarining o'zi (bu sandbox'da Docker mavjud emasligi sababli)
sinalmagan - bu loyihaning boshqa Docker-bog'liq qismlari
(`docs_DOCKER_DEPLOYMENT.md`) bilan bir xil halol cheklov.
