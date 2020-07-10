# blrcode
Return rcode including checking for blacklies style NXDOMAIN

This program takes a DNS name and type, queries it, and returns
the response code (rcode), e.g. NOERROR, NXDOMAIN, FORMERR,
SERVFAIL, NOTIMP, etc. It uses the locally configured default
DNS resolver to perform the lookup.

If using a validating resolver, it also tries to detect if the
name is in a DNSSEC signed zone that employs the gruesome hack
known as "Black Lies", described in this expired Internet-draft:

    https://tools.ietf.org/html/draft-valsorda-dnsop-black-lies-00

If so, it attempts to infer whether a NOERROR response is actually
a non-existent domain name. With Black Lies, the nameserver responds
to a non-existent name with a NOERROR/NODATA response (!!), and a
single NSEC record in the AUTHORITY section that includes only
NSEC and RRSIG in its type bitmap. Put another way, the nameserver
claims that the non-existent name actually does exist, but that it
does not have any resource records of the type it was asked for.

Unfortunately, this hack results in non-existent names being
responded to in a way that is indistinguishable from Empty
Non-Terminal names (which do exist).

At the current time, Cloudflare and NS1 are known to implement
Black Lies. Cloudflare actually has an additional hack to differentiate
the empty non-terminal case. Instead of the correct response for an
ENT, it returns a made up jumble of other RR types in the type bitmap.
Ugly as it is, NS1 should probably do the same.

There are diagnostic and analysis tools that rely on obtaining
correct DNS response codes. So, there needs to be a reliable way
of inferring the real response code in spite of these hacks.

