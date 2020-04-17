# `gcr.io/paketo-buildpacks/encrypt-at-rest`
The Paketo Encrypt At Rest Buildpack is a Cloud Native Buildpack that AES encrypts an application layer and then decrypts it at launch time.

## Behavior
This buildpack will participate any of the following conditions are met

* `$BP_EAR_KEY` is set to a hex-encoded AES key

The buildpack will do the following:

* AES encrypts the contents of `<APPLICATION_ROOT>` using Cipher Feedback (CFB) mode and a randomly generated initial vector
* Removes the source code in `<APPLICATION_ROOT>`
* Contributes a `profile.d` script the decrypts the application before launching

## Configuration
| Environment Variable | Description
| -------------------- | -----------
| `$BP_EAR_KEY` | Configure the AES key to use at build time.
| `$BPL_EAR_KEY` | Configure the AES key to use at launch time.


## License
This buildpack is released under version 2.0 of the [Apache License][a].

[a]: http://www.apache.org/licenses/LICENSE-2.0
