# blrcode
Return rcode including checking for blacklies style NXDOMAIN

This program takes a DNS name and type, queries it, and returns
the response code (rcode), e.g. NOERROR, NXDOMAIN, FORMERR,
SERVFAIL, NOTIMP, etc. It uses the locally configured default
DNS resolver to perform the lookup.

If using a validating resolver, it also tries to detect if the
name is in a DNSSEC signed zone that employs the hack known as
"Black Lies", described in this expired Internet-draft:

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
ENT, it appears to return in the NSEC bitmap the complete set of RR types
that it supports except the RR type received in the query. That's quite
ugly, and has the additional side effect of not being able to distinguish
Empty Non-Terminals from other types of NODATA responses. Furthermore, it
may cause issues with resolvers that implement aggressive NSEC caching
together with RR type inference.

I've made an enhancement request to NS1 to implement another method
to distinguish non-existence from an empty non-terminal response. The
specific proposal under consideration is to add a private RRtype to the
NSEC bitmap of Empty Non-Terminal responses.

[Update: As of April 20th 2021, NS1 has implemented this request.
For Empty Non-Terminal responses, they now add an additional private
RRtype, currently 65281, to the type bitmap. This allows these responses
to be distinguished from NXDOMAIN. This sentinal type can now also be
used to identify Empty Non-Terminals.]

There are diagnostic and analysis tools that rely on obtaining
correct DNS response codes. So, there needs to be a reliable way
of inferring the real response status in spite of these hacks.
