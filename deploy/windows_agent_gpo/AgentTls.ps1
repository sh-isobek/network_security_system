# AgentTls.ps1 - Agent API bilan HTTPS (ichki CA) uchun umumiy funksiyalar.
#
# Deploy-NetworkSecurityAgent.ps1 va Watchdog-NetworkSecurityAgent.ps1
# shu faylni dot-source qiladi:  . (Join-Path $dir "AgentTls.ps1")
#
# XAVFSIZLIK: ichki CA (deploy/pki/generate_ca.sh, paketdagi agent-ca.crt)
# Windows'ning umumiy "Trusted Root" do'koniga QO'SHILMAYDI. Aks holda
# serverdagi CA kaliti bilan istalgan sayt (bank, pochta...) uchun soxta
# sertifikat yasab, barcha kompyuterlarda brauzer trafigini o'qish mumkin
# bo'lardi. Buning o'rniga faqat SHU PowerShell jarayoni, faqat SHU CA
# imzolagan sertifikatga qo'shimcha ishonadi (Python agent esa
# AGENT_CA_BUNDLE_FILE orqali xuddi shunday). Sertifikat nomi (IP/host) va
# muddati baribir to'liq tekshiriladi - faqat "noma'lum ildiz" xatosi
# bizning CA bo'lsagina kechiriladi.

function Enable-AgentCaTrust {
    param([Parameter(Mandatory = $true)][string]$CaFile)
    if (-not (Test-Path $CaFile)) { throw "CA fayli topilmadi: $CaFile" }
    # PowerShell 5.1 standart holatda TLS 1.0/1.1 bilan ulanadi - nginx esa faqat 1.2+ qabul qiladi
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    # Python agent ham proksini chetlab o'tadi - serverga to'g'ridan-to'g'ri
    [System.Net.WebRequest]::DefaultWebProxy = $null
    if (-not ("NsaAgentCaTrust" -as [type])) {
        Add-Type -TypeDefinition @"
using System;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

public static class NsaAgentCaTrust {
    private static X509Certificate2 ca;

    public static void Install(string caPath) {
        ca = new X509Certificate2(caPath);
        ServicePointManager.ServerCertificateValidationCallback = Validate;
    }

    public static bool Validate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors) {
        if (errors == SslPolicyErrors.None) return true;
        if (ca == null || certificate == null) return false;
        // Nom mos kelmasligi yoki sertifikat yo'qligi HECH QACHON kechirilmaydi
        if ((errors & ~SslPolicyErrors.RemoteCertificateChainErrors) != SslPolicyErrors.None) return false;
        using (X509Chain own = new X509Chain()) {
            own.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            own.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
            own.ChainPolicy.ExtraStore.Add(ca);
            if (!own.Build(new X509Certificate2(certificate))) return false;
            if (own.ChainElements.Count < 2) return false;
            X509Certificate2 root = own.ChainElements[own.ChainElements.Count - 1].Certificate;
            return String.Equals(root.Thumbprint, ca.Thumbprint, StringComparison.OrdinalIgnoreCase);
        }
    }
}
"@
    }
    [NsaAgentCaTrust]::Install((Resolve-Path $CaFile).Path)
}

function ConvertTo-AgentHttpsUrl {
    # http://172.16.1.206:8443 -> https://172.16.1.206:9443 (server IP'si repoda saqlanmaydi -
    # SYSVOL .env'dagi mavjud manzildan olinadi)
    param([Parameter(Mandatory = $true)][string]$HttpUrl, [int]$Port = 9443)
    $u = [Uri]$HttpUrl
    return "https://$($u.Host):$Port"
}

function Test-AgentHttpsUrl {
    # Server shu HTTPS manzilda ishlayaptimi va sertifikati bizning CA'dan ekanmi?
    param([Parameter(Mandatory = $true)][string]$Url, [Parameter(Mandatory = $true)][string]$CaFile)
    try {
        Enable-AgentCaTrust -CaFile $CaFile
        $resp = Invoke-WebRequest -Uri "$($Url.TrimEnd('/'))/api/v1/health" -UseBasicParsing -TimeoutSec 10
        return ($resp.StatusCode -eq 200)
    } catch {
        return $false
    }
}
