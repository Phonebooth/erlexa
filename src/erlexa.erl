-module(erlexa).

-include_lib("hackney/include/hackney_lib.hrl").
-include_lib("public_key/include/public_key.hrl").

-export([
    verify_signature/3
]).

%%====================================================================
%% API functions
%%====================================================================
verify_signature(RequestBody, Signature, CertificateURL) ->
    case verify_cert_url(CertificateURL) of
        true ->
            CertChain = [Cert | _] = get_cert_chain(CertificateURL),
            OtpCert = public_key:pkix_decode_cert(Cert, otp),
            verify_cert_chain(CertChain) andalso
            verify_cert_domain(OtpCert) andalso
            verify_signature_ll(RequestBody, Signature, OtpCert);
        false ->
            false
    end.

%%====================================================================
%% Internal functions
%%====================================================================
verify_cert_url(CertURL) ->
    URL = hackney_url:parse_url(CertURL),
    URL#hackney_url.scheme == https andalso
    URL#hackney_url.host == "s3.amazonaws.com" andalso
    binary:match(URL#hackney_url.path, <<"/echo.api/">>, []) == {0, 10} andalso
    URL#hackney_url.port == 443.

verify_cert_chain(CertChain) ->
    [RootCert] = pem_to_certs(root_cert_pem()),
    case public_key:pkix_path_validation(RootCert, lists:reverse(CertChain), []) of
        {ok, _} -> true;
        _ -> false
    end.

verify_cert_domain(OtpCert) ->
    case ssl_verify_hostname:verify_cert_hostname(OtpCert, "echo-api.amazon.com") of
        {valid, _} -> true;
        _ -> false
    end.

verify_signature_ll(RequestBody, Signature, OtpCert) ->
    Key = get_public_key(OtpCert),
    public_key:verify(RequestBody, sha, base64:decode(Signature), Key).

get_cert_chain(CertURL) ->
    {ok, Pem} = download_pem(CertURL),
    pem_to_certs(Pem).

pem_to_certs(Pem) ->
    [Cert || {'Certificate', Cert, not_encrypted}
        <- public_key:pem_decode(Pem)].

get_public_key(OtpCert) ->
    TBSCert = OtpCert#'OTPCertificate'.tbsCertificate,
    PublicKeyInfo = TBSCert#'OTPTBSCertificate'.subjectPublicKeyInfo,
    PublicKeyInfo#'OTPSubjectPublicKeyInfo'.subjectPublicKey.

download_pem(URL) ->
    {ok, 200, _, Ref} = hackney:request(URL),
    {ok, Body} = hackney:body(Ref),
    {ok, Body}.

root_cert_pem() ->
% Downloaded from https://www.symantec.com/content/dam/symantec/docs/other-resources/verisign-class-3-public-primary-certification-authority-g5-en.pem
<<"-----BEGIN CERTIFICATE-----
MIIE0zCCA7ugAwIBAgIQGNrRniZ96LtKIVjNzGs7SjANBgkqhkiG9w0BAQUFADCB
yjELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQL
ExZWZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwNiBWZXJp
U2lnbiwgSW5jLiAtIEZvciBhdXRob3JpemVkIHVzZSBvbmx5MUUwQwYDVQQDEzxW
ZXJpU2lnbiBDbGFzcyAzIFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0
aG9yaXR5IC0gRzUwHhcNMDYxMTA4MDAwMDAwWhcNMzYwNzE2MjM1OTU5WjCByjEL
MAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQLExZW
ZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwNiBWZXJpU2ln
biwgSW5jLiAtIEZvciBhdXRob3JpemVkIHVzZSBvbmx5MUUwQwYDVQQDEzxWZXJp
U2lnbiBDbGFzcyAzIFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0aG9y
aXR5IC0gRzUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCvJAgIKXo1
nmAMqudLO07cfLw8RRy7K+D+KQL5VwijZIUVJ/XxrcgxiV0i6CqqpkKzj/i5Vbex
t0uz/o9+B1fs70PbZmIVYc9gDaTY3vjgw2IIPVQT60nKWVSFJuUrjxuf6/WhkcIz
SdhDY2pSS9KP6HBRTdGJaXvHcPaz3BJ023tdS1bTlr8Vd6Gw9KIl8q8ckmcY5fQG
BO+QueQA5N06tRn/Arr0PO7gi+s3i+z016zy9vA9r911kTMZHRxAy3QkGSGT2RT+
rCpSx4/VBEnkjWNHiDxpg8v+R70rfk/Fla4OndTRQ8Bnc+MUCH7lP59zuDMKz10/
NIeWiu5T6CUVAgMBAAGjgbIwga8wDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8E
BAMCAQYwbQYIKwYBBQUHAQwEYTBfoV2gWzBZMFcwVRYJaW1hZ2UvZ2lmMCEwHzAH
BgUrDgMCGgQUj+XTGoasjY5rw8+AatRIGCx7GS4wJRYjaHR0cDovL2xvZ28udmVy
aXNpZ24uY29tL3ZzbG9nby5naWYwHQYDVR0OBBYEFH/TZafC3ey78DAJ80M5+gKv
MzEzMA0GCSqGSIb3DQEBBQUAA4IBAQCTJEowX2LP2BqYLz3q3JktvXf2pXkiOOzE
p6B4Eq1iDkVwZMXnl2YtmAl+X6/WzChl8gGqCBpH3vn5fJJaCGkgDdk+bW48DW7Y
5gaRQBi5+MHt39tBquCWIMnNZBU4gcmU7qKEKQsTb47bDN0lAtukixlE0kF6BWlK
WE9gyn6CagsCqiUXObXbf+eEZSqVir2G3l6BFoMtEMze/aiCKm0oHw0LxOXnGiYZ
4fQRbxC1lfznQgUy286dUV4otp6F01vvpX1FQHKOtw5rDgb7MzVIcbidJ4vEZV8N
hnacRHr2lVz2XTIIM6RUthg/aFzyQkqFOFSDX9HoLPKsEdao7WNq
-----END CERTIFICATE-----">>.

%%====================================================================
%% Tests
%%====================================================================
-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

verify_cert_url_test_() -> [
    ?_assertEqual(true,  verify_cert_url(<<"https://s3.amazonaws.com/echo.api/echo-api-cert-4.pem">>)),
    ?_assertEqual(false, verify_cert_url(<<"http://s3.amazonaws.com/echo.api/echo-api-cert-4.pem">>)),
    ?_assertEqual(false, verify_cert_url(<<"https://s4.amazonaws.com/echo.api/echo-api-cert-4.pem">>)),
    ?_assertEqual(false, verify_cert_url(<<"https://s3.amazonaws.com:841/echo.api/echo-api-cert-4.pem">>)),
    ?_assertEqual(false, verify_cert_url(<<"https://s3.amazonaws.com/echo-api/echo-api-cert-4.pem">>))
].

verify_cert_chain_test() ->
    ?assertEqual(true, verify_cert_chain(pem_to_certs(test_pem_certs()))).

verify_cert_domain_test() ->
    [Cert | _] = pem_to_certs(test_pem_certs()),
    OtpCert = public_key:pkix_decode_cert(Cert, otp),
    ?assertEqual(true, verify_cert_domain(OtpCert)).

verify_signature_ll_test() ->
    % TODO: generate certs and signature on the fly

    Body = <<"{\"version\":\"1.0\",\"session\":{\"new\":true,\"sessionId\":\"123\",\"application\":{\"applicationId\":\"123\"},\"attributes\":{},\"user\":{\"userId\":\"123\"}},\"request\":{\"type\":\"IntentRequest\",\"requestId\":\"123\",\"timestamp\":\"2017-04-13T13:33:49Z\",\"intent\":{\"name\":\"SampleIntent\"}}}">>,

    Signature = <<"mMjezw0FlDuweHrC7/48EeAHMmnvV6lCsyKcWbR44XA16XnEIaMIg8gDfuUItf0igObVi+f+IIJjia8nC2YaMzyN27HuRSXoCQSQ5a2adYuWMptnDoobUaPaBrkhiIP7GW4COOrG3XhG+asJiD1c+uNsysd85DoneuUvdMXiYAs+4L8i+GUk0D0zneGnsPMlrqIt8j1q4jy58T0zX8LqYPfbQf7cxAZqoEtKZOYQM7txcbb8qCRpfCJa85kfDp7BihFa8U2XXJcC/iT+MBk33X8bciCWlksflE/UID5VdR/QUPllmsWgP/Cy9paQeXI8oiEeiaEK2c268990cV20Xw==">>,

    [Cert | _] = pem_to_certs(test_pem_certs()),
    OtpCert = public_key:pkix_decode_cert(Cert, otp),

    ?assertEqual(true, verify_signature_ll(Body, Signature, OtpCert)).


test_pem_certs() ->
    <<"-----BEGIN CERTIFICATE-----
MIIFfjCCBGagAwIBAgIQPyXKruWqg4+pHAUadfxxnTANBgkqhkiG9w0BAQsFADB+
MQswCQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xHzAd
BgNVBAsTFlN5bWFudGVjIFRydXN0IE5ldHdvcmsxLzAtBgNVBAMTJlN5bWFudGVj
IENsYXNzIDMgU2VjdXJlIFNlcnZlciBDQSAtIEc0MB4XDTE2MTAwNzAwMDAwMFoX
DTE3MTAzMDIzNTk1OVowbTELMAkGA1UEBhMCVVMxEzARBgNVBAgMCldhc2hpbmd0
b24xEDAOBgNVBAcMB1NlYXR0bGUxGTAXBgNVBAoMEEFtYXpvbi5jb20sIEluYy4x
HDAaBgNVBAMME2VjaG8tYXBpLmFtYXpvbi5jb20wggEiMA0GCSqGSIb3DQEBAQUA
A4IBDwAwggEKAoIBAQCcr7MGu5EDVOduBAbET5vheJNNnIOQbAnrTrwAaxdCaC32
VWELwJNMLjB1Hk1eixuhXr/rfCitAI2jjXZywFWNTLcfX9USz7kq/4CIA5S4qgF8
RTzMC8cJzsaY4pSA2J1wMDQxKnHdlMxIYZuR9ouKRHOd7qcVnqM06eSpO0YPpKsI
hiAs0CtJxig/MhxcTKkcWuiCfOtHgR7Rhx58ZnJLzVip6/+WWLTV0CBG+mcC3Lry
thObGQ2HNRIboghsUcjFckoARMCQaIolyBml8bbU6TkOTfIasRJj8gPk6fG8zGJd
KdfCG3wkPpt3Xm6LS08NrzkHSOlkuWipBl7bqhGjAgMBAAGjggIHMIICAzAeBgNV
HREEFzAVghNlY2hvLWFwaS5hbWF6b24uY29tMAkGA1UdEwQCMAAwDgYDVR0PAQH/
BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjBhBgNVHSAEWjBY
MFYGBmeBDAECAjBMMCMGCCsGAQUFBwIBFhdodHRwczovL2Quc3ltY2IuY29tL2Nw
czAlBggrBgEFBQcCAjAZDBdodHRwczovL2Quc3ltY2IuY29tL3JwYTAfBgNVHSME
GDAWgBRfYM9hkFXfhEMUimAqsvV69EMY7zArBgNVHR8EJDAiMCCgHqAchhpodHRw
Oi8vc3Muc3ltY2IuY29tL3NzLmNybDBXBggrBgEFBQcBAQRLMEkwHwYIKwYBBQUH
MAGGE2h0dHA6Ly9zcy5zeW1jZC5jb20wJgYIKwYBBQUHMAKGGmh0dHA6Ly9zcy5z
eW1jYi5jb20vc3MuY3J0MA8GAytlTQQIMAYCAQECAQEwgYsGCisGAQQB1nkCBAIE
fQR7AHkAdwCnzkpOYgfgrd7l/apLH4Z2h2e10AKlXUcxDn5nCpXqsgAAAVefqkBK
AAAEAwBIMEYCIQDKa3wGnBQLd06NZO2V1KWekjSeBKo8cbME8yx0vIV/gQIhAPoV
LPhVi6Coe1Fat1ItG+FyV0DhKAQjCd0nT+6l6ztiMA0GCSqGSIb3DQEBCwUAA4IB
AQB7hqbnqGsZJXk4AQi36tocJeKIq0YSARfcaoBjUyTIlxPHAgbvP+E8yl7f9DYB
lyy5ZliCatzWiw+zrn9WB9A21q6K+CTNltfxtNtY5xQ0MDHykrF+bu+DhyoP1YbM
DR2oWmd+SrTGVA6RMrW8VkRTPgOI+DCxtnV7fbiKuChG8Is7bc7H8kMZq36lb4ZZ
Ld3sRSLK8zHIuBpOVD+9v01mG1NLrlRkZduIpSW8gqe0En8K/0pVUlknpmoJBVdD
8QnjDZDKB00lgWbw5HLLfM2wdHredPcEDP7rmnjDSDhkxRBtVCVWyHSvdoAFpuyD
resu4y+Ob3GCo2J3XCv0Cvog
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFODCCBCCgAwIBAgIQUT+5dDhwtzRAQY0wkwaZ/zANBgkqhkiG9w0BAQsFADCB
yjELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQL
ExZWZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwNiBWZXJp
U2lnbiwgSW5jLiAtIEZvciBhdXRob3JpemVkIHVzZSBvbmx5MUUwQwYDVQQDEzxW
ZXJpU2lnbiBDbGFzcyAzIFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0
aG9yaXR5IC0gRzUwHhcNMTMxMDMxMDAwMDAwWhcNMjMxMDMwMjM1OTU5WjB+MQsw
CQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xHzAdBgNV
BAsTFlN5bWFudGVjIFRydXN0IE5ldHdvcmsxLzAtBgNVBAMTJlN5bWFudGVjIENs
YXNzIDMgU2VjdXJlIFNlcnZlciBDQSAtIEc0MIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAstgFyhx0LbUXVjnFSlIJluhL2AzxaJ+aQihiw6UwU35VEYJb
A3oNL+F5BMm0lncZgQGUWfm893qZJ4Itt4PdWid/sgN6nFMl6UgfRk/InSn4vnlW
9vf92Tpo2otLgjNBEsPIPMzWlnqEIRoiBAMnF4scaGGTDw5RgDMdtLXO637QYqzu
s3sBdO9pNevK1T2p7peYyo2qRA4lmUoVlqTObQJUHypqJuIGOmNIrLRM0XWTUP8T
L9ba4cYY9Z/JJV3zADreJk20KQnNDz0jbxZKgRb78oMQw7jW2FUyPfG9D72MUpVK
Fpd6UiFjdS8W+cRmvvW1Cdj/JwDNRHxvSz+w9wIDAQABo4IBYzCCAV8wEgYDVR0T
AQH/BAgwBgEB/wIBADAwBgNVHR8EKTAnMCWgI6Ahhh9odHRwOi8vczEuc3ltY2Iu
Y29tL3BjYTMtZzUuY3JsMA4GA1UdDwEB/wQEAwIBBjAvBggrBgEFBQcBAQQjMCEw
HwYIKwYBBQUHMAGGE2h0dHA6Ly9zMi5zeW1jYi5jb20wawYDVR0gBGQwYjBgBgpg
hkgBhvhFAQc2MFIwJgYIKwYBBQUHAgEWGmh0dHA6Ly93d3cuc3ltYXV0aC5jb20v
Y3BzMCgGCCsGAQUFBwICMBwaGmh0dHA6Ly93d3cuc3ltYXV0aC5jb20vcnBhMCkG
A1UdEQQiMCCkHjAcMRowGAYDVQQDExFTeW1hbnRlY1BLSS0xLTUzNDAdBgNVHQ4E
FgQUX2DPYZBV34RDFIpgKrL1evRDGO8wHwYDVR0jBBgwFoAUf9Nlp8Ld7LvwMAnz
Qzn6Aq8zMTMwDQYJKoZIhvcNAQELBQADggEBAF6UVkndji1l9cE2UbYD49qecxny
H1mrWH5sJgUs+oHXXCMXIiw3k/eG7IXmsKP9H+IyqEVv4dn7ua/ScKAyQmW/hP4W
Ko8/xabWo5N9Q+l0IZE1KPRj6S7t9/Vcf0uatSDpCr3gRRAMFJSaXaXjS5HoJJtG
QGX0InLNmfiIEfXzf+YzguaoxX7+0AjiJVgIcWjmzaLmFN5OUiQt/eV5E1PnXi8t
TRttQBVSK/eHiXgSgW7ZTaoteNTCLD0IX4eRnh8OsN4wUmSGiaqdZpwOdgyA8nTY
Kvi4Os7X1g8RvmurFPW9QaAiY4nxug9vKWNmLT+sjHLF+8fk1A/yO0+MKcc=
-----END CERTIFICATE-----">>.

-endif.
