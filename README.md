# Illegal Security Chip

This is super illegal even without a proper key. Please **DO NOT** use it. Otherwise $\*\*y will definitely sue you to death **IMMEDIATELY**!!!!!!!!!!!!111!!!!

-- S** FUDs

(LOL we somehow got mentioned on psxhax https://www.psxhax.com/threads/ps5tools-added-to-ps5-github-repository-by-skfu-invites-contributors.8264/)

## WTF?

This is a JavaCard applet that emulates the [A7105 security chip](https://gist.github.com/dogtopus/dae307c7773e792150990a06e79583d0) found in PS4 licensed controllers (at APDU level). It signs random challenges (nonce) sent from the host using an on-card RSA 2048 key (DS4Key). When sending the signature back, it also presents some identifying information and the public key (both combined forms DS4ID) to the host.

**LIABILITY NOTICE**: This applet enables **NEITHER** controller counterfeiting nor circumventing the PS4 peripheral authentication by default. It is **NOT** intended to be used for any illegal activities. The word "Illegal" in the project name is a joke in case you didn't get it already. No keys are provided for obvious reasons. Also I am not responsible for anything you will do with this applet.

## Card Requirements

The card must satisfy all of the following in order to be able to install and run IllegalSecurityChip:

- JavaCard API >= 3.0.1 (for `Signature.ALG_RSA_SHA_256_PKCS1_PSS`)
- Properly implements `Signature.ALG_RSA_SHA_256_PKCS1_PSS` (Rare! Most random 3.0.1+ cards don't have this!)
  - Applet installation will fail with random error code (e.g. Applet installation error, unspecified error, condition not satisfied, or the "intended error code" function not supported) depending on the JavaCard implementation if this is not supported.
  - If the card does not support RSA 2048, it might fail with the same "function not supported". However this is much rarer (like who tf still make JavaCards that don't support RSA 2048 in 2020).
- Approx. 512 bytes of transient memory. (Can be shrunk to just approx. 256 by merging the buffer used in `JediIdentity` with the top-level applet one)

The only card I came across that has `Signature.ALG_RSA_SHA_256_PKCS1_PSS` implemented is J3H145, which seems to run JCOP 3.x. However I believe that JCOP 2.4.2 cards like J2D081 should also work since the original A7105 security chip seem to run the exact same OS and also conveniently offers JavaCard API 3.0.1.

It should also be possible to install and run IllegalSecurityChip on a blank JCOP A710x (i.e. A710xCG). However I am unable to source such chip in manageable quantities and thus unable to test.

In short, devices that work and are tested:

- J3H145 from [SmartcardFocus](https://www.smartcardfocus.com/shop/ilp/id~879/nxp-j3h145-dual-interface-java-card-144k/p/index.shtml)

Devices that might work but are untested:

- J3D081 from ~~[SmartcardFocus](https://www.smartcardfocus.com/shop/ilp/id~688/j3d081-80k/p/index.shtml)~~ (No longer available on SmartcardFocus)
- J2D081 (SIM cut) from Aliexpress (if properly pre-personalized which they don't always do. Always ask!) or [Futako (T=0)](https://www.javacardsdk.com/product/j2d081simt0/)
- [Fidesmo Card v1.0](https://shop.fidesmo.com/products/fidesmo-card) (J3D145 NFC only) and [Fidesmo Card v2.0](https://shop.fidesmo.com/products/fidesmo-card-2-0) (J3H145 NFC only)
- NXP A710xCG (e.g. on [Digi-key](https://www.digikey.com/en/products/detail/nxp-usa-inc/A7101CGTK2-T0B040X/7645426))
- G\&D SmartCafe Expert 7.0 Card/Security Dongle
  - https://www.commoncriteriaportal.org/files/epfiles/1028b_pdf.pdf section 8.1.1.2, FCS\_COP.1.1/RSA-CRT-SIGN: "The TSF shall perform signature generation in accordance with a specified cryptographic algorithm RSA-CRT and cryptographic key sizes 512 up to 4096 bit that meet the following: scheme 1 of \[ISO9796-2\] chapter 8, \[RSA\] (RSASSAPKCS1-v15) chapter 8, **\[RSASSA-PSS\]** and \[RSA-SHA-RFC2409\].")
- J3R180 from [Futako](https://www.javacardsdk.com/product/j3r180sim/) and potentially other places.

## Building and Usage

Simply run `ant` to build after checking out the submodules with `git submodule update --init --recursive`

To install the applet with GlobalPlatformPro, use:

```sh
gp --install IllegalSecurityChip.cap
```

### Personalization Script

IllegalSecurityChip comes with a personalization script under [utils/iscctl/](./utils/iscctl/). To use it, run

```sh
pipenv install
```

then

```sh
pipenv run ./iscctl.py --help
```

Refer to the built-in help for detailed usage.

**NOTE**: This applet does not support atomic operations. That is, interrupting all operations that write data to the card (i.e. updating DS4ID/DS4Key and any of their parts) can corrupt the data and make the applet unusable. In this case you might need to run `nuke` command or reinstantiate the applet via GlobalPlatform. All data saved on the card that belong to this applet will be deleted permanently.

#### Generating keys on-card

```sh
pipenv run ./iscctl.py gen-key
```

#### Importing existing DS4Key

```sh
pipenv run ./iscctl.py import-ds4key <path-to-ds4key-file>
```

**NOTE**: For those who are curious, DS4Key is basically the same format as `jedi_cert.bin`. Speaking more and the "Illegal" word in our name will no longer be a joke ;-).

#### Testing authentication

```sh
pipenv run ./iscctl.py test-auth [-c path-to-ca] [-p page-size]
```

This command should also work on A7105 security chip given proper bridge hardware between CCID over USB (or other protocol over other link supported by Microsoft Smart Card Base or pcsclite) and NXP SCI2C.

If `page-size` is 0, iscctl will try to send/receive the whole challenge/response block in one single extended length APDU. Otherwise it will send/receive in chunks of `page-size` bytes. It is unknown whether extended length APDU or 0 `page-size` is actually supported by A7105 security chip so be careful when setting `page-size` to 0 when running `test-auth` on A7105. `page-size` is set to 0x80 by default.

You can optionally specify the Jedi CA with the `-c` parameter so that iscctl will validate the signature of DS4ID on the card as well.

#### Changing the DS4ID serial number

```sh
pipenv run ./iscctl.py set-serial <new-16-byte-serial-number>
```

Note that changing the serial number will void the signature and it needs to be re-signed before any future authentications.

#### DS4ID signing using test CA

If this is not obvious enough: Test CA is only for testing and will NOT work on real PS4 without the 8-minute timeout.

First make sure that you generate the test CA key pair (no certificates needed, just the keys). The keys can be generated by using e.g. OpenSSL and they need to be encoded in plaintext PEM or DER format. Only RSA 2048 is supported since that is what $**y's DS4 authentication scheme was built on.

To sign the DS4ID using the test CA, use

```sh
pipenv run ./iscctl.py sign-ds4id -c <your-ca-private-key>
```
