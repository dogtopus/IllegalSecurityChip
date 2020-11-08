# Illegal Security Chip

This is super illegal even without a proper key. Please **DO NOT** use it. Otherwise $\*\*y will definitely sue you to death **IMMEDIATELY**!!!!!!!!!!!!111!!!!

-- S** FUDs

## Card Requirements

The card must satisfy all of the following in order to be able to install and run IllegalSecurityChip:

- JavaCard API >= 3.0.1 (for `Signature.ALG_RSA_SHA_256_PKCS1_PSS`)
- Properly implements `Signature.ALG_RSA_SHA_256_PKCS1_PSS` (Rare! Most random 3.0.1+ cards don't have this!)
- Approx. 512 bytes of transient memory. (Can be shrunk to just approx. 256 by merging the buffer used in `JediIdentity` with the top-level applet one)

The only card I came across that has `Signature.ALG_RSA_SHA_256_PKCS1_PSS` implemented is J3H145, which seems to run JCOP 3.x. However I believe that JCOP 2.4.2 cards like J2D081 should also work since the original A7105 security chip seem to run the exact same OS and also conveniently offers JavaCard API 3.0.1.

It should also be possible to install and run IllegalSecurityChip on a blank JCOP A710x (i.e. A710xCG). However I am unable to source such chip in manageable quantities and thus unable to test.

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

Refer to the built-in help for usage. TODO add more info for e.g. key import/export, testing authentication, terminating/nuking the applet here.
