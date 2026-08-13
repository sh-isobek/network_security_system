# SSH orqali GitHub'dan Avtomatik Deploy (Auto-Update)

Bu hujjat production serveringizni (masalan sizning
`network1411tas-Virtual-Machine`) GitHub'ga **SSH orqali** ulab,
`main` branch'ga yangi commit tushganda **avtomatik ravishda**
yangilanadigan qilib sozlashni tushuntiradi.

## 0. Qanday ruxsatlar kerak? (qisqacha javob)

**MUHIM tushuncha**: bu — **chiquvchi (outbound)** SSH ulanish
(server -> GitHub). Serveringizda hech qanday **kiruvchi (inbound)**
port ochish yoki firewall qoidasini o'zgartirish SHART EMAS - GitHub
sizning serveringizga hech qachon ulanmaydi, faqat serveringiz
GitHub'ga ulanadi (xuddi `git clone`/`git pull` qilganingizdek).

| Nima kerak | Nima uchun | Qanday berish |
|---|---|---|
| **Chiquvchi TCP 22-port** (`github.com`ga) | `git fetch`/`pull` SSH orqali ishlaydi | Odatda standart - agar qattiq firewall bo'lsa, `443`-portli SSH muqobilini pastda ko'ring |
| **`docker` guruhi a'zoligi** | Docker buyruqlarini `root`siz ishga tushirish uchun | `usermod -aG docker netsecdeploy` |
| **`/opt/network_security_system` papkasiga egalik** | `git pull`, log yozish uchun | `chown -R netsecdeploy:netsecdeploy /opt/network_security_system` |
| SSH kalit fayl ruxsatlari | SSH o'zi buzilgan ruxsatlar bilan kalitni RAD ETADI | `chmod 600` (shaxsiy), `chmod 700` (`.ssh` papka) |

**Kerak EMAS**: `sudo`, `root`, yangi firewall qoidasi (kiruvchi), SSH
serverining o'zini sozlash (`/etc/ssh/sshd_config`) - bularning
hech biriga tegish shart emas.

### 0.1. Maxsus foydalanuvchi yaratish (root o'rniga)

`root` sifatida ishlatish **kerakidan ortiqcha huquq** beradi (agar
skript yoki bog'liqliklardan birortasi buzilsa, butun serverga kirish
imkoni bo'ladi). Buning o'rniga faqat kerakli huquqqa ega maxsus
foydalanuvchi yarating:

```bash
sudo useradd --system --create-home --shell /bin/bash netsecdeploy
sudo usermod -aG docker netsecdeploy
```

`docker` guruhi a'zoligi - bu Docker'ning o'zi tavsiya qiladigan
standart amaliyot (`/var/run/docker.sock` guruh egaligi orqali,
`root` bo'lmagan foydalanuvchiga `docker`/`docker compose`
buyruqlarini ishlatish imkonini beradi).

**Diqqat**: `docker` guruhiga a'zolik amalda root-ekvivalent huquq
beradi (Docker konteynerlar orqali host fayl tizimiga kirish mumkin)
- bu **Docker'ning o'zining tanilgan xususiyati**, bizning
konfiguratsiyamizning kamchiligi emas. Agar bu sizning xavfsizlik
siyosatingizga mos kelmasa, muqobil: Podman (rootless konteynerlar)
yoki Docker'ni rootless rejimda ishga tushirish
(https://docs.docker.com/engine/security/rootless/).

## 1. SSH Deploy Key yaratish (serverda)

**Muhim**: shaxsiy SSH kalitingizni ishlatmang - repo uchun alohida,
**faqat o'qish huquqiga ega** (read-only) "deploy key" yarating. Bu
xavfsizroq - agar server buzilsa, tajovuzkor faqat shu bitta repo'ni
o'qiy oladi, boshqa hech narsaga yozib ham, boshqa repo'larga kira
ham olmaydi.

Kalit `netsecdeploy` foydalanuvchisi nomidan (root'dan emas)
yaratiladi - `sudo -u` orqali:

```bash
sudo -u netsecdeploy mkdir -p /home/netsecdeploy/.ssh
sudo -u netsecdeploy ssh-keygen -t ed25519 -f /home/netsecdeploy/.ssh/network_security_deploy_key -N "" -C "network-security-deploy@$(hostname)"
sudo -u netsecdeploy cat /home/netsecdeploy/.ssh/network_security_deploy_key.pub
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
sudo -u netsecdeploy tee -a /home/netsecdeploy/.ssh/config << 'EOF'
Host github.com-network-security
    HostName github.com
    User git
    IdentityFile /home/netsecdeploy/.ssh/network_security_deploy_key
    IdentitiesOnly yes
EOF

# SSH kalit fayl ruxsatlari - agar bular noto'g'ri bo'lsa, SSH
# "UNPROTECTED PRIVATE KEY FILE" xatoligi bilan kalitni rad etadi
sudo -u netsecdeploy chmod 700 /home/netsecdeploy/.ssh
sudo -u netsecdeploy chmod 600 /home/netsecdeploy/.ssh/network_security_deploy_key
sudo -u netsecdeploy chmod 644 /home/netsecdeploy/.ssh/network_security_deploy_key.pub
sudo -u netsecdeploy chmod 600 /home/netsecdeploy/.ssh/config
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
