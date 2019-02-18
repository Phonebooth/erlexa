-module(erlexa).

%%-include_lib("hackney/include/hackney_lib.hrl").
-include_lib("public_key/include/public_key.hrl").

-export([
    verify_signature/3,

    verify_cert_url/1,
    get_cert_chain/1
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
    URL = http_uri:parse(CertURL),
    {ok, {Scheme, _, Host, Port, Path, _}} = URL,
    Scheme == https andalso Host == "s3.amazonaws.com" andalso
    binary:match(list_to_binary(Path), <<"/echo.api/">>, []) == {0, 10} andalso
    Port == 443.

verify_cert_chain(CertChain) ->
    [RootCert | Rest] = lists:reverse(CertChain),
    case public_key:pkix_path_validation(RootCert, Rest, []) of
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
    {ok, Pem} = case cache:get(cert_cache, CertURL) of
        undefined ->
            {ok, P} = download_pem(CertURL),
            cache:put(cert_cache, CertURL, P),
            {ok, P};
        V ->
            {ok, V}
    end,
    pem_to_certs(Pem).

pem_to_certs(Pem) ->
    [Cert || {'Certificate', Cert, not_encrypted}
        <- public_key:pem_decode(Pem)].

get_public_key(OtpCert) ->
    TBSCert = OtpCert#'OTPCertificate'.tbsCertificate,
    PublicKeyInfo = TBSCert#'OTPTBSCertificate'.subjectPublicKeyInfo,
    PublicKeyInfo#'OTPSubjectPublicKeyInfo'.subjectPublicKey.

download_pem(URL) ->
    case ibrowse:send_req(URL, [], get, [], [{is_ssl, true}, {ssl_options, [{verify,verify_none}, {depth, 3}]}]) of
        {error, Error} ->
            {error, Error};
        {ok,"200",_,Body} ->
            {ok, list_to_binary(Body)}
    end.
%%    {ok, 200, _, Ref} = hackney:request(URL),
%%    {ok, Body} = hackney:body(Ref),
%%    {ok, Body}.

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

    Body = <<"{\"version\":\"1.0\",\"session\":{\"new\":true,\"sessionId\":\"123\",\"application\":{\"applicationId\":\"amzn1.ask.skill.28c32583-4c23-48de-9745-cbb8bf051873\"},\"user\":{\"userId\":\"123\"}},\"context\":{\"System\":{\"application\":{\"applicationId\":\"amzn1.ask.skill.28c32583-4c23-48de-9745-cbb8bf051873\"},\"user\":{\"userId\":\"123\"},\"device\":{\"deviceId\":\"123\",\"supportedInterfaces\":{}},\"apiEndpoint\":\"https://api.amazonalexa.com\",\"apiAccessToken\":\"123\"}},\"request\":{\"type\":\"LaunchRequest\",\"requestId\":\"amzn1.echo-api.request.f94374cb-a3ee-46c2-8aea-1afc33b9fad5\",\"timestamp\":\"2018-07-03T12:37:46Z\",\"locale\":\"en-US\",\"shouldLinkResultBeReturned\":false}}">>,

    Signature = <<"AzMyoQSXTd2D9kYPDj38HBUtM72wdNXdXYy039+6vvV0RQce2vzrXjTSftNXgmotkc9zWasGjF/MwPi290PCuXNeMc0pqJs5hM/tCkRYjlDA49T2d1Vqc8P5gS3d+WHX9zBpac5u6fR5AyONIQqQiiA0r5KDTIhVtG+A55/nWqgVMegXNhnYyuIrTID+eUiesayHWG9F57ShsASpaQjQMaCzc40Dd/CmI3MCIOFtSwL02kjjVK8hxitgFsmxk/PVZGj744E/Wx/KektuQATBbkaizW2kGcYUJdliTNt4wN/qnuQ0o7eUwptS7nwFdc9E8huLH6HTXNy2C/QGcFzBXQ==">>,

    [Cert | _] = pem_to_certs(test_pem_certs()),
    OtpCert = public_key:pkix_decode_cert(Cert, otp),

    ?assertEqual(true, verify_signature_ll(Body, Signature, OtpCert)).


test_pem_certs() ->
    <<"-----BEGIN CERTIFICATE-----
MIIFcDCCBFigAwIBAgIQB6krbZc11OZ5l2/FnU3CpTANBgkqhkiG9w0BAQsFADBG
MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRUwEwYDVQQLEwxTZXJ2ZXIg
Q0EgMUIxDzANBgNVBAMTBkFtYXpvbjAeFw0xODA2MTMwMDAwMDBaFw0xOTA2MTMx
MjAwMDBaMB4xHDAaBgNVBAMTE2VjaG8tYXBpLmFtYXpvbi5jb20wggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCFTKdiYc8w7wt59nCfHzpT9xy8mDk8spkC
ECPzIC1Qim9T7dSRsT7tcUJIOHMPXxrlxyySSK1qB7LLdoDFuhW/CtUdD4c6t73y
ryNHQzhPZ7fQvb8jMWf5VWPTNsS1FBAKZdTe6n0pjIAS4nypxfF+eXMaQrHiH4Ib
iV+aZP7Men40j/YucEeii8ukmfmlQ8L351BUZmCD1FZlXD+fLb5YgbZjC+c6TB0K
WI2oe3qK0zFKGigaFvNBoZl1A+v0V7AFWZ+tYKfCvyVBuwase5pK4770GKNfqXaX
a/q1p5N1M3D6qa6j/U01IOtn9gJqB+PvVKBVZ/TcfBJVHtdDj+aPAgMBAAGjggKA
MIICfDAfBgNVHSMEGDAWgBRZpGYGUqB7lZI8o5QHJ5Z0W/k90DAdBgNVHQ4EFgQU
PmgdPNeivSJ4aVavb6e7hsUZfg0wHgYDVR0RBBcwFYITZWNoby1hcGkuYW1hem9u
LmNvbTAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUF
BwMCMDsGA1UdHwQ0MDIwMKAuoCyGKmh0dHA6Ly9jcmwuc2NhMWIuYW1hem9udHJ1
c3QuY29tL3NjYTFiLmNybDAgBgNVHSAEGTAXMAsGCWCGSAGG/WwBAjAIBgZngQwB
AgEwdQYIKwYBBQUHAQEEaTBnMC0GCCsGAQUFBzABhiFodHRwOi8vb2NzcC5zY2Ex
Yi5hbWF6b250cnVzdC5jb20wNgYIKwYBBQUHMAKGKmh0dHA6Ly9jcnQuc2NhMWIu
YW1hem9udHJ1c3QuY29tL3NjYTFiLmNydDAMBgNVHRMBAf8EAjAAMIIBBQYKKwYB
BAHWeQIEAgSB9gSB8wDxAHcAu9nfvB+KcbWTlCOXqpJ7RzhXlQqrUugakJZkNo4e
0YUAAAFj+wW/FAAABAMASDBGAiEAo5ajttPYYb/u06ZYvQ1A+wXljlscciiJQO2J
q+aZmwQCIQDTytC4r5crkEOvnIu/SVEQF83XnnXoqa1Hc8GZubzjSgB2AId1v+dZ
fPiMQ5lfvfNu/1aNR1Y2/0q1YMG06v9eoIMPAAABY/sFv6UAAAQDAEcwRQIgc1ob
hd3vnx2CPLjFqNy/98zvyfh6LkZhSRJgp/kOv1oCIQDPB9E24+ifg9btt7F4ae0e
v7x2QubFqHTV0mbbPIdRmzANBgkqhkiG9w0BAQsFAAOCAQEAnxhNKdhvKOmcY1xZ
f0C2BBfsezzIm1MlxSThk8UXhMgNdnFAjhb6PUneR7ea/ls/KuyLhVvE5A1i/z5Y
P3jiwq8qfCa/WQeRpZ4wxCqOWwK0hWR1iDZeL7z6+YSmOkrJru2TpOMf9DaExaVs
jVgzC6N0FAOgosicCUojJGZKHDwgh/2UoXdLSKuvXJcOGijZ+v1/7BjBwlaYecEN
0Gx1UkhBoJLFjUgAuEdiGLN8SyZce2geddK+ekTfAGmAvXe1ILFQid/CIoqVUO8b
EpQT6CLezn1LfucP7FsHjUqUeknlsMi3KSvCPccM8VWwoM7PM2krWqSYveDC4dVx
4xynhA==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIESTCCAzGgAwIBAgITBn+UV4WH6Kx33rJTMlu8mYtWDTANBgkqhkiG9w0BAQsF
ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6
b24gUm9vdCBDQSAxMB4XDTE1MTAyMjAwMDAwMFoXDTI1MTAxOTAwMDAwMFowRjEL
MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEVMBMGA1UECxMMU2VydmVyIENB
IDFCMQ8wDQYDVQQDEwZBbWF6b24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQDCThZn3c68asg3Wuw6MLAd5tES6BIoSMzoKcG5blPVo+sDORrMd4f2AbnZ
cMzPa43j4wNxhplty6aUKk4T1qe9BOwKFjwK6zmxxLVYo7bHViXsPlJ6qOMpFge5
blDP+18x+B26A0piiQOuPkfyDyeR4xQghfj66Yo19V+emU3nazfvpFA+ROz6WoVm
B5x+F2pV8xeKNR7u6azDdU5YVX1TawprmxRC1+WsAYmz6qP+z8ArDITC2FMVy2fw
0IjKOtEXc/VfmtTFch5+AfGYMGMqqvJ6LcXiAhqG5TI+Dr0RtM88k+8XUBCeQ8IG
KuANaL7TiItKZYxK1MMuTJtV9IblAgMBAAGjggE7MIIBNzASBgNVHRMBAf8ECDAG
AQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUWaRmBlKge5WSPKOUByeW
dFv5PdAwHwYDVR0jBBgwFoAUhBjMhTTsvAyUlC4IWZzHshBOCggwewYIKwYBBQUH
AQEEbzBtMC8GCCsGAQUFBzABhiNodHRwOi8vb2NzcC5yb290Y2ExLmFtYXpvbnRy
dXN0LmNvbTA6BggrBgEFBQcwAoYuaHR0cDovL2NydC5yb290Y2ExLmFtYXpvbnRy
dXN0LmNvbS9yb290Y2ExLmNlcjA/BgNVHR8EODA2MDSgMqAwhi5odHRwOi8vY3Js
LnJvb3RjYTEuYW1hem9udHJ1c3QuY29tL3Jvb3RjYTEuY3JsMBMGA1UdIAQMMAow
CAYGZ4EMAQIBMA0GCSqGSIb3DQEBCwUAA4IBAQCFkr41u3nPo4FCHOTjY3NTOVI1
59Gt/a6ZiqyJEi+752+a1U5y6iAwYfmXss2lJwJFqMp2PphKg5625kXg8kP2CN5t
6G7bMQcT8C8xDZNtYTd7WPD8UZiRKAJPBXa30/AbwuZe0GaFEQ8ugcYQgSn+IGBI
8/LwhBNTZTUVEWuCUUBVV18YtbAiPq3yXqMB48Oz+ctBWuZSkbvkNodPLamkB2g1
upRyzQ7qDn1X8nn8N8V7YJ6y68AtkHcNSRAnpTitxBKjtKPISLMVCx7i4hncxHZS
yLyKQXhw2W2Xs0qLeC1etA+jTGDK4UfLeC0SF7FSi8o5LL21L8IzApar2pR/
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIEkjCCA3qgAwIBAgITBn+USionzfP6wq4rAfkI7rnExjANBgkqhkiG9w0BAQsF
ADCBmDELMAkGA1UEBhMCVVMxEDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNj
b3R0c2RhbGUxJTAjBgNVBAoTHFN0YXJmaWVsZCBUZWNobm9sb2dpZXMsIEluYy4x
OzA5BgNVBAMTMlN0YXJmaWVsZCBTZXJ2aWNlcyBSb290IENlcnRpZmljYXRlIEF1
dGhvcml0eSAtIEcyMB4XDTE1MDUyNTEyMDAwMFoXDTM3MTIzMTAxMDAwMFowOTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJv
b3QgQ0EgMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALJ4gHHKeNXj
ca9HgFB0fW7Y14h29Jlo91ghYPl0hAEvrAIthtOgQ3pOsqTQNroBvo3bSMgHFzZM
9O6II8c+6zf1tRn4SWiw3te5djgdYZ6k/oI2peVKVuRF4fn9tBb6dNqcmzU5L/qw
IFAGbHrQgLKm+a/sRxmPUDgH3KKHOVj4utWp+UhnMJbulHheb4mjUcAwhmahRWa6
VOujw5H5SNz/0egwLX0tdHA114gk957EWW67c4cX8jJGKLhD+rcdqsq08p8kDi1L
93FcXmn/6pUCyziKrlA4b9v7LWIbxcceVOF34GfID5yHI9Y/QCB/IIDEgEw+OyQm
jgSubJrIqg0CAwEAAaOCATEwggEtMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/
BAQDAgGGMB0GA1UdDgQWBBSEGMyFNOy8DJSULghZnMeyEE4KCDAfBgNVHSMEGDAW
gBScXwDfqgHXMCs4iKK4bUqc8hGRgzB4BggrBgEFBQcBAQRsMGowLgYIKwYBBQUH
MAGGImh0dHA6Ly9vY3NwLnJvb3RnMi5hbWF6b250cnVzdC5jb20wOAYIKwYBBQUH
MAKGLGh0dHA6Ly9jcnQucm9vdGcyLmFtYXpvbnRydXN0LmNvbS9yb290ZzIuY2Vy
MD0GA1UdHwQ2MDQwMqAwoC6GLGh0dHA6Ly9jcmwucm9vdGcyLmFtYXpvbnRydXN0
LmNvbS9yb290ZzIuY3JsMBEGA1UdIAQKMAgwBgYEVR0gADANBgkqhkiG9w0BAQsF
AAOCAQEAYjdCXLwQtT6LLOkMm2xF4gcAevnFWAu5CIw+7bMlPLVvUOTNNWqnkzSW
MiGpSESrnO09tKpzbeR/FoCJbM8oAxiDR3mjEH4wW6w7sGDgd9QIpuEdfF7Au/ma
eyKdpwAJfqxGF4PcnCZXmTA5YpaP7dreqsXMGz7KQ2hsVxa81Q4gLv7/wmpdLqBK
bRRYh5TmOTFffHPLkIhqhBGWJ6bt2YFGpn6jcgAKUj6DiAdjd4lpFw85hdKrCEVN
0FE6/V1dN2RMfjCyVSRCnTawXZwXgWHxyvkQAiSr6w10kY17RSlQOYiypok1JR4U
akcjMS9cmvqtmg5iUaQqqcT5NJ0hGA==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIEdTCCA12gAwIBAgIJAKcOSkw0grd/MA0GCSqGSIb3DQEBCwUAMGgxCzAJBgNV
BAYTAlVTMSUwIwYDVQQKExxTdGFyZmllbGQgVGVjaG5vbG9naWVzLCBJbmMuMTIw
MAYDVQQLEylTdGFyZmllbGQgQ2xhc3MgMiBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0
eTAeFw0wOTA5MDIwMDAwMDBaFw0zNDA2MjgxNzM5MTZaMIGYMQswCQYDVQQGEwJV
UzEQMA4GA1UECBMHQXJpem9uYTETMBEGA1UEBxMKU2NvdHRzZGFsZTElMCMGA1UE
ChMcU3RhcmZpZWxkIFRlY2hub2xvZ2llcywgSW5jLjE7MDkGA1UEAxMyU3RhcmZp
ZWxkIFNlcnZpY2VzIFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IC0gRzIwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDVDDrEKvlO4vW+GZdfjohTsR8/
y8+fIBNtKTrID30892t2OGPZNmCom15cAICyL1l/9of5JUOG52kbUpqQ4XHj2C0N
Tm/2yEnZtvMaVq4rtnQU68/7JuMauh2WLmo7WJSJR1b/JaCTcFOD2oR0FMNnngRo
Ot+OQFodSk7PQ5E751bWAHDLUu57fa4657wx+UX2wmDPE1kCK4DMNEffud6QZW0C
zyyRpqbn3oUYSXxmTqM6bam17jQuug0DuDPfR+uxa40l2ZvOgdFFRjKWcIfeAg5J
Q4W2bHO7ZOphQazJ1FTfhy/HIrImzJ9ZVGif/L4qL8RVHHVAYBeFAlU5i38FAgMB
AAGjgfAwge0wDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0O
BBYEFJxfAN+qAdcwKziIorhtSpzyEZGDMB8GA1UdIwQYMBaAFL9ft9HO3R+G9FtV
rNzXEMIOqYjnME8GCCsGAQUFBwEBBEMwQTAcBggrBgEFBQcwAYYQaHR0cDovL28u
c3MyLnVzLzAhBggrBgEFBQcwAoYVaHR0cDovL3guc3MyLnVzL3guY2VyMCYGA1Ud
HwQfMB0wG6AZoBeGFWh0dHA6Ly9zLnNzMi51cy9yLmNybDARBgNVHSAECjAIMAYG
BFUdIAAwDQYJKoZIhvcNAQELBQADggEBACMd44pXyn3pF3lM8R5V/cxTbj5HD9/G
VfKyBDbtgB9TxF00KGu+x1X8Z+rLP3+QsjPNG1gQggL4+C/1E2DUBc7xgQjB3ad1
l08YuW3e95ORCLp+QCztweq7dp4zBncdDQh/U90bZKuCJ/Fp1U1ervShw3WnWEQt
8jxwmKy6abaVd38PMV4s/KCHOkdp8Hlf9BRUpJVeEXgSYCfOn8J3/yNTd126/+pZ
59vPr5KW7ySaNRB6nJHGDn2Z9j8Z3/VyVOEVqQdZe4O/Ui5GjLIAZHYcSNPYeehu
VsyuLAOQ1xk4meTKCRlb/weWsKh/NEnfVqn3sF/tM+2MR7cwA130A4w=
-----END CERTIFICATE-----">>.

-endif.
