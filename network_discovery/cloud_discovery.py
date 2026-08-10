"""
Cloud Asset Discovery (AWS/Azure/GCP) - network_discovery paketi.

HALOL CHEKLOV: bu loyiha tayyorlangan sandbox muhitida haqiqiy
bulutli hisob (AWS/Azure/GCP credentials) mavjud emas - shuning uchun
bu modul (VMware/Hyper-V bilan bir xil andozada) real API
chaqiruvlarini to'g'ri qurgan, lekin credentials sozlanmagan holatda
**graceful fail** qiladigan qilib yozilgan - bu xatti-harakat real
testda tasdiqlangan.

Har biri rasmiy SDK'dan foydalanadi:
  - AWS: `boto3` (rasmiy AWS SDK)
  - Azure: `azure-mgmt-compute` (rasmiy Azure SDK)
  - GCP: `google-cloud-compute` (rasmiy GCP SDK)
"""
import logging
import os
from dataclasses import dataclass
from typing import List, Optional

logger = logging.getLogger("cloud_discovery")


@dataclass
class CloudInstance:
    instance_id: str
    name: Optional[str] = None
    private_ip: Optional[str] = None
    public_ip: Optional[str] = None
    state: Optional[str] = None
    provider: str = "unknown"  # "aws" | "azure" | "gcp"
    region: Optional[str] = None


def discover_aws_instances(region: str = None, timeout: int = 15) -> List[CloudInstance]:
    """
    AWS EC2 instance'larini oladi. Autentifikatsiya standart AWS
    usullari orqali (`~/.aws/credentials`, muhit o'zgaruvchilari,
    yoki IAM rol) - `boto3`ning o'zi buni avtomatik hal qiladi.
    """
    region = region or os.getenv("AWS_REGION", "us-east-1")

    try:
        import boto3
        from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError
    except ImportError:
        logger.error("'boto3' kutubxonasi o'rnatilmagan - 'pip install boto3' bilan qo'shing")
        return []

    try:
        ec2 = boto3.client("ec2", region_name=region)
        response = ec2.describe_instances()

        instances = []
        for reservation in response.get("Reservations", []):
            for inst in reservation.get("Instances", []):
                name = next((t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"), None)
                instances.append(CloudInstance(
                    instance_id=inst["InstanceId"],
                    name=name,
                    private_ip=inst.get("PrivateIpAddress"),
                    public_ip=inst.get("PublicIpAddress"),
                    state=inst.get("State", {}).get("Name"),
                    provider="aws",
                    region=region,
                ))

        logger.info(f"AWS discovery ({region}): {len(instances)} ta instance topildi")
        return instances

    except NoCredentialsError:
        logger.warning("AWS credentials sozlanmagan (~/.aws/credentials yoki muhit o'zgaruvchilari)")
        return []
    except (BotoCoreError, ClientError) as exc:
        logger.error(f"AWS'ga ulanib bo'lmadi: {exc}")
        return []


def discover_azure_instances(subscription_id: str = None, timeout: int = 15) -> List[CloudInstance]:
    """Azure Virtual Machine'larini oladi (`azure-mgmt-compute` orqali)."""
    subscription_id = subscription_id or os.getenv("AZURE_SUBSCRIPTION_ID", "")
    if not subscription_id:
        logger.warning("AZURE_SUBSCRIPTION_ID sozlanmagan")
        return []

    try:
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.compute import ComputeManagementClient
    except ImportError:
        logger.error("'azure-mgmt-compute'/'azure-identity' o'rnatilmagan")
        return []

    try:
        credential = DefaultAzureCredential()
        client = ComputeManagementClient(credential, subscription_id)

        instances = [
            CloudInstance(
                instance_id=vm.vm_id, name=vm.name,
                state=vm.provisioning_state, provider="azure",
                region=vm.location,
            )
            for vm in client.virtual_machines.list_all()
        ]
        logger.info(f"Azure discovery: {len(instances)} ta VM topildi")
        return instances

    except Exception as exc:
        logger.error(f"Azure'ga ulanib bo'lmadi: {exc}")
        return []


def discover_gcp_instances(project_id: str = None, zone: str = None, timeout: int = 15) -> List[CloudInstance]:
    """GCP Compute Engine instance'larini oladi (`google-cloud-compute` orqali)."""
    project_id = project_id or os.getenv("GCP_PROJECT_ID", "")
    zone = zone or os.getenv("GCP_ZONE", "")
    if not project_id or not zone:
        logger.warning("GCP_PROJECT_ID/GCP_ZONE sozlanmagan")
        return []

    try:
        from google.cloud import compute_v1
    except ImportError:
        logger.error("'google-cloud-compute' o'rnatilmagan")
        return []

    try:
        client = compute_v1.InstancesClient()
        instances = [
            CloudInstance(
                instance_id=str(inst.id), name=inst.name,
                state=inst.status, provider="gcp", region=zone,
            )
            for inst in client.list(project=project_id, zone=zone)
        ]
        logger.info(f"GCP discovery ({zone}): {len(instances)} ta instance topildi")
        return instances

    except Exception as exc:
        logger.error(f"GCP'ga ulanib bo'lmadi: {exc}")
        return []
