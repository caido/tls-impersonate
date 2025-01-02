# TLS Impersonate

This library is for TLS impersonification **only**. The goal is to try tofool a WAF by micmicking the `JA3`/`JA4` fingerprint.

## Limitations

The impersonification is never perfect, it usually also requires modifications at the application layer.

- You will not fool `JA4H` though unless you set the proper HTTP headers
- If you do `Http/1.1` only, `JA4` will see it and might block you
- We don't do TLS extension ordering, so older `JA3` WAF might block you (Chrome also randomizes since 2023)

## Support for TLS library

Currently this library is built for `OpenSSL`, but we have made it possible to support other libraries.
Feel free to send a PR if you wish to see wider support.

## Resources

- [TLS Fingerprinting with JA3 and JA3S](https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967/)
- [JA4+ Network Fingerprinting](https://blog.foxio.io/ja4%2B-network-fingerprinting)

## Credits

We took a lot of inspiration from [rquest](https://github.com/penumbra-x/rquest), if you need a simple to use/ready-to-go client you should look at that crate.
