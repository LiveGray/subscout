# Subscout
subscout is a simple, nimble subdomain enumeration tool written in Rust language. It is designed to help bug bounty hunters, security professionals and penetration testers discover subdomains of a given target domain.

<!-- PROJECT SHIELDS -->
<!--
*** I'm using markdown "reference style" links for readability.
*** Reference links are enclosed in brackets [ ] instead of parentheses ( ).
*** See the bottom of this document for the declaration of the reference variables
*** for contributors-url, forks-url, etc. This is an optional, concise syntax you may use.
*** https://www.markdownguide.org/basic-syntax/#reference-style-links
-->
[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![MIT License][license-shield]][license-url]

Sources:
- Alienvault
- Anubis
- Crtsh
- Hackertarget
- Omnisint (FYI - This site is down often.)
- Threatminer

<!-- ROADMAP -->
## Usage
```console
$ ./subscout -t hackthissite.org
```
```console
$ ./subscout -t hackthissite.org -o hackthesite.txt
```

<!-- ROADMAP -->
## Build
```console
$ git clone https://github.com/dom-sec/subscout
$ cd subscout
$ cargo build --release
$ cd target/release
$ ./subscout -t hackthissite.org
```

<!-- ROADMAP -->
## Output
```console
$ ./subscout -t facebook.com
www.m.facebook.com------------step1-----acc---verify.digi-worx.com
cpanel.the--facebook.com
mail.the--facebook.com
the--facebook.com
webdisk.the--facebook.com
webmail.the--facebook.com
www.the--facebook.com
proxygen_verifier.facebook.com
m.facebook.com-----------n.slickgt.com.br
www.m.facebook.com-----------n.slickgt.com.br
m.facebook.com---------terms-of-service.digi-worx.com
www.m.facebook.com---------terms-of-service.digi-worx.com
m.facebook.com----------step1---confirm.sorgu2.com
www.m.facebook.com----------step1---confirm.sorgu2.com
m.facebook.com------login---step1.akuevi.net
www.m.facebook.com------login---step1.akuevi.net
m.facebook.com-----validate---read---new---tos.yudumay.com
www.m.facebook.com-----validate---read---new---tos.yudumay.com
m.facebook.com----securelogin--confirm.wpthm.ir
www.m.facebook.com----securelogin--confirm.wpthm.ir
news--facebook.com
tihonoff@facebook.com
china--facebook.com
www.china--facebook.com
thefacebook.com

[subscout]> Successfully scraped 11712 subdomains from facebook.com in 81.238776082s
```

<!-- ROADMAP -->
## Roadmap

* More passive sources for domain reconnaissance
* Builtwith API integration
* HTTP response code checks
* Improved exception handling
* IP validation
* URI parameter parsing
* DB integration via PostgreSQL

See the [open issues](https://github.com/dom-sec/subscout/issues) for a list of proposed features (and known issues).

<!-- CONTRIBUTING -->
## Contributing

Contributions are what make the open source community such an amazing place to be learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

<!-- ISSUES AND REQUESTS -->
## Issues and requests

If you have a problem or a feature request, open an [issue](https://github.com/dom-sec/subscout/issues).

<!-- STARGAZERS -->
## Stargazers over time

[![Stargazers over time](https://starchart.cc/dom-sec/subscout.svg)](https://starchart.cc/dom-sec/subscout)

<!-- CONTRIBUTORS -->
## Contributors
This project exists thanks to all the people who contribute. [See the contributors list](https://github.com/dom-sec/subscout/graphs/contributors).
