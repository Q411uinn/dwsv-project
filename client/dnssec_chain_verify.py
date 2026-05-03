import dns.resolver
import dns.dnssec
import dns.name
import dns.rdatatype

resolver = dns.resolver.Resolver()
resolver.use_edns(0, dns.flags.DO, 1232)


def get_rrset_with_rrsig(domain, rtype):
    answer = resolver.resolve(domain, rtype)
    rrset = answer.rrset

    rrsig = None
    for rr in answer.response.answer:
        if rr.rdtype == dns.rdatatype.RRSIG and rr.covers == rrset.rdtype:
            rrsig = rr

    return rrset, rrsig


def get_dnskey(zone):
    answer = resolver.resolve(zone, 'DNSKEY')
    return answer.rrset


def verify_txt_with_dnssec(domain, zone):
    try:
        # 1. TXT + RRSIG
        rrset, rrsig = get_rrset_with_rrsig(domain, 'TXT')

        if rrsig is None:
            print("❌ 无RRSIG")
            return None

        # 2. DNSKEY
        dnskey = get_dnskey(zone)

        # 3. 验证签名
        dns.dnssec.validate(
            rrset,
            rrsig,
            {dns.name.from_text(zone): dnskey}
        )

        print("✅ DNSSEC 验证成功")

        return rrset

    except Exception as e:
        print("❌ DNSSEC 验证失败:", e)
        return None
