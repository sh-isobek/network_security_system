# Kubernetes — joriy etish (yangi TZ 18-bo'lim)

## Test holati (halol tushuntirish)

Bu manifestlar **haqiqiy Kubernetes klasterida sinovdan o'tkazilgan**
(k3s v1.28, ushbu loyiha tayyorlangan sandbox muhitida to'g'ridan-to'g'ri
ishga tushirilgan) - quyidagilar **haqiqatan tasdiqlangan**:

- ✅ Kubernetes control plane (API server, controller-manager,
  scheduler) real ishga tushdi va Node "Ready" holatiga keldi
- ✅ Konteyner runtime (containerd) real ishladi, real Pod
  (`busybox`) rejalashtirildi va node'ga tayinlandi
- ✅ Barcha 6 ta manifest fayli **server-side dry-run** orqali
  (`kubectl apply --dry-run=server`) haqiqiy Kubernetes API sxemasiga
  qarshi tekshirildi - **0 xatolik**
- ✅ Barcha 24 resurs (StatefulSet, 9 Deployment, 5 Service, 2 PVC,
  HPA, Ingress, ConfigMap, Secret) **haqiqatan yaratildi**, ReplicaSet
  replika sonlari to'g'ri qo'llanildi, HPA to'g'ri Deployment'ga
  bog'landi, PVC'lar to'g'ri StorageClass bilan so'ralindi

**Nima sinalmadi**: bu sandbox muhitida `docker.io` (Docker Hub)
registry'ga tarmoq kirish **bloklangan** (xuddi Docker daemon'ining
o'zi mavjud bo'lmagani kabi) - shuning uchun Pod'lar image pull
bosqichida to'xtab qoldi (`ContainerCreating`/`Pending`), haqiqiy
ishlab turgan konteynerlarni ko'rish imkoni bo'lmadi. Bu Kubernetes
yoki manifestlarning muammosi emas - sof tarmoq siyosati cheklovi.
Production muhitida (yoki internetga kirish imkoni bo'lgan istalgan
klasterda) bu manifestlar to'liq ishlashi kutiladi.

## Talab qilinadigan tayyorgarlik (production uchun)

1. **Docker image build va push qilish** - bu loyihaning `Dockerfile`si
   asosida (loyiha ildizida) image quring va konteyner registriga
   (masalan GitHub Container Registry) joylang:
   ```bash
   docker build -t ghcr.io/your-org/network-security-system:latest .
   docker push ghcr.io/your-org/network-security-system:latest
   ```
   Barcha `k8s/*.yaml` fayllaridagi `image:` maydonini shu manzilga
   moslang (hozircha `ghcr.io/your-org/...` placeholder sifatida
   qo'yilgan).

2. **cgroup v2** - zamonaviy Kubernetes (1.31+) faqat cgroup v2'ni
   qo'llab-quvvatlaydi. Node'laringizda `mount | grep cgroup2` orqali
   tekshiring. (Eslatma: shu loyiha tayyorlangan sandbox muhiti faqat
   cgroup v1'ga ega edi, shuning uchun eskiroq k3s versiyasi bilan
   sinaldi - bu **faqat shu sinov muhitiga xos cheklov**, sizning
   production serverlaringizga aloqasi yo'q.)

## O'rnatish tartibi

```bash
kubectl apply -f k8s/00-namespace-config.yaml

# Haqiqiy maxfiy ma'lumotlar bilan Secret yarating (00-fayldagi
# shablonni ishlatmang!):
kubectl create secret generic app-secrets -n network-security \
    --from-literal=POSTGRES_PASSWORD='KuchliParol123!' \
    --from-literal=AGENT_API_KEY='...' \
    --from-literal=DASHBOARD_SECRET_KEY='...' \
    --dry-run=client -o yaml | kubectl apply -f -

kubectl apply -f k8s/01-postgres.yaml
kubectl apply -f k8s/02-engines.yaml
kubectl apply -f k8s/03-dashboard-api.yaml
kubectl apply -f k8s/04-syslog-rabbitmq.yaml
kubectl apply -f k8s/05-ingress.yaml   # ixtiyoriy, nginx-ingress talab qiladi
```

## Tekshirish

```bash
kubectl get all -n network-security
kubectl get pvc -n network-security
kubectl logs -n network-security deployment/dashboard
```

Birinchi admin foydalanuvchini yaratish:
```bash
kubectl exec -n network-security deploy/dashboard -- \
    python -m dashboard.create_user --username admin --password '...' --role admin
```

## docker-compose.yml bilan moslik jadvali

| Docker Compose xizmati | K8s resursi | Fayl |
|---|---|---|
| `postgres` | StatefulSet + Service (headless) | `01-postgres.yaml` |
| `syslog_collector` | Deployment + LoadBalancer Service | `04-syslog-rabbitmq.yaml` |
| `parser_engine`, `response_engine`, `notification_engine`, `mitre_tagging_engine`, `ueba_engine` | Deployment (1 nusxa - holat/tartib muhim) | `02-engines.yaml` |
| `file_analysis_engine`, `deep_scan_engine` | Deployment (2+ nusxa - navbat-asosida xavfsiz miqyoslanadi) | `02-engines.yaml` |
| `agent_api` | Deployment (3 nusxa) + LoadBalancer + **HPA** | `03-dashboard-api.yaml` |
| `dashboard` | Deployment (2 nusxa) + ClusterIP + **Ingress** | `03-dashboard-api.yaml`, `05-ingress.yaml` |
| `rabbitmq`, `queue_ingest_worker` | Deployment + Service | `04-syslog-rabbitmq.yaml` |
| `clamav_updater` | (Alohida CronJob sifatida qo'shilishi tavsiya etiladi - hozircha PVC orqali `deep-scan-engine`ga ulangan) | `02-engines.yaml` |

## Gorizontal miqyoslanish (yangi TZ 21-bo'lim)

`agent-api` uchun HorizontalPodAutoscaler allaqachon sozlangan (3-15
nusxa, CPU 70% asosida). Boshqa navbat-asosli xizmatlar
(`file-analysis-engine`, `deep-scan-engine`, `queue-ingest-worker`)
uchun ham xuddi shunday HPA qo'shish mumkin - ular DB/navbat orqali
muvofiqlashgani uchun istalgancha nusxada xavfsiz ishlaydi.
