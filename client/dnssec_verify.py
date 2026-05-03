import dns.resolver
import dns.dnssec
import dns.name
import dns.exception
import dns.rdatatype
import dns.flags

# 强制使用本地 DNS
resolver = dns.resolver.Resolver()
resolver.nameservers = ["127.0.0.1"]  
resolver.use_edns(0, dns.flags.DO, 1232)  # 开启 DNSSEC


def get_txt_and_rrsig(domain):
    """
    获取 TXT 记录 和 对应的 RRSIG
    """
    answer = resolver.resolve(domain, 'TXT')

    rrset = answer.rrset

    rrsig = None
    for rr in answer.response.answer:
        if rr.rdtype == dns.rdatatype.RRSIG:
            if rr.covers == dns.rdatatype.TXT:
                rrsig = rr

    print("DEBUG RRSET:", rrset)
    print("DEBUG RRSIG:", rrsig)

    return rrset, rrsig


def get_dnskey(zone):
    """
    获取 DNSKEY
    """
    answer = resolver.resolve(zone, 'DNSKEY')
    return answer.rrset


def dnssec_verify(domain, zone):
    """
    DNSSEC 验证主函数
    """
    try:
        rrset, rrsig = get_txt_and_rrsig(domain)

        if rrsig is None:
            print("❌ 没有 RRSIG，无法验证")
            return False

        dnskey = get_dnskey(zone)

        # 🔥 执行 DNSSEC 验证
        dns.dnssec.validate(
            rrset,
            rrsig,
            {dns.name.from_text(zone): dnskey}
        )

        print("✅ DNSSEC 验证成功")
        return True

    except dns.exception.DNSException as e:
        print("❌ DNSSEC 验证失败:", e)
        return False


if __name__ == "__main__":
    domain = "_auth.example.com"
    zone = "example.com"

    dnssec_verify(domain, zone)
