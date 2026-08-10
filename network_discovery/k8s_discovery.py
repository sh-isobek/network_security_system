"""
Kubernetes Node Discovery - network_discovery paketi.

`kubectl` CLI orqali ishlaydi (rasmiy Python `kubernetes` client
kutubxonasi o'rniga - kamroq bog'liqlik, `KUBECONFIG` orqali istalgan
klaster bilan ishlaydi, xuddi administrator qo'lda ishlatadigandek).
"""
import json
import logging
import os
import subprocess
from dataclasses import dataclass
from typing import List, Optional

logger = logging.getLogger("k8s_discovery")


@dataclass
class K8sNode:
    name: str
    internal_ip: Optional[str] = None
    os_image: Optional[str] = None
    kubelet_version: Optional[str] = None
    ready: bool = False


def discover_k8s_nodes(kubeconfig: Optional[str] = None, timeout: int = 15) -> List[K8sNode]:
    """
    `kubectl get nodes -o json` orqali klasterdagi barcha node'larni
    oladi. Klasterga ulanib bo'lmasa (masalan KUBECONFIG noto'g'ri
    yoki klaster ishlamayapti), bo'sh ro'yxat qaytaradi.
    """
    env = os.environ.copy()
    if kubeconfig:
        env["KUBECONFIG"] = kubeconfig

    try:
        result = subprocess.run(
            ["kubectl", "get", "nodes", "-o", "json"],
            capture_output=True, text=True, timeout=timeout, env=env,
        )
    except FileNotFoundError:
        logger.error("kubectl topilmadi")
        return []
    except subprocess.TimeoutExpired:
        logger.error(f"k8s discovery timeout ({timeout}s)")
        return []

    if result.returncode != 0:
        logger.warning(f"kubectl xatoligi (klaster ishlamayotgan bo'lishi mumkin): {result.stderr[:200]}")
        return []

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        logger.error("kubectl JSON chiqishini parslab bo'lmadi")
        return []

    nodes = []
    for item in data.get("items", []):
        status = item.get("status", {})
        node_info = status.get("nodeInfo", {})
        addresses = {a["type"]: a["address"] for a in status.get("addresses", [])}
        conditions = status.get("conditions", [])
        ready = any(c.get("type") == "Ready" and c.get("status") == "True" for c in conditions)

        nodes.append(K8sNode(
            name=item.get("metadata", {}).get("name", "unknown"),
            internal_ip=addresses.get("InternalIP"),
            os_image=node_info.get("osImage"),
            kubelet_version=node_info.get("kubeletVersion"),
            ready=ready,
        ))

    logger.info(f"Kubernetes discovery: {len(nodes)} ta node topildi")
    return nodes
