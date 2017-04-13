# erlexa

An Erlang library to help with signature verification of an Alexa request when implementing [Alexa Skill](https://developer.amazon.com/alexa-skills-kit).

Based on [Amazon Alexa documentation](https://developer.amazon.com/public/solutions/alexa/alexa-skills-kit/docs/developing-an-alexa-skill-as-a-web-service#checking-the-signature-of-the-request).

## Usage

    erlexa:verify_signature(RequestBody, Signature, CertificateURL).
