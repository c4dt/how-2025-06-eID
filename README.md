# Hands-on Workshop on E-ID

This repository holds the files and explanations for the hands-on workshop on
electronic identities, created by the https://c4dt.epfl.ch for its partners
on the 26th of June 2025.
The goal of this hands-on workshop is to:

- introduce you to our [Taxonomy](https://eid-privacy.github.io/wp1/2025/06/10/taxonomy-101.html)
  - explain what the **legal texts** for the Swiss E-ID require
  - how these requirements match with common **trust and threat** models
  - which **cryptographic protocols** allow us to implement the needed functionality

The hands-on workshop is in two parts:

- Morning: presentation by Dr. Imad Aad, including discussion time
- Afternoon: hands-on workshop using Jupyter notebooks

# Afternoon - Practical Part

In the afternoon, we present the following:

1. The Swiyu test environment - how it works, how our taxonomy describes it, and current limitations
2. Potential next developments in electronic identities, specifically related to **holder binding**
and **unlinkability**

## Swiyu Test Environment

Follow the text in the Jupyter Notebook for [1-Swiyu](./1-Swiyu.ipynb).

## Unlinkability and Holder Binding

Follow the text in the Jupyter Notebook for [2-BBS-ECDSA](./2-BBS-ECDSA.ipynb).
The exercises in this Jupyter Notebook are based on the excellent work of:

- [Cloudflare's ZKAttest](https://github.com/cloudflare/zkp-ecdsa) which shows how to prove an ECDSA
signature with a public key committed to a **Tom-256** curve
- [Ubique's SHIELDS](https://github.com/UbiqueInnovation/zkattest-rs/) takes the idea of ZKAttest
and applies it to BBS signatures and the holder binding / unlinkability problem
- [Docknetwork/Crypto Library](https://github.com/docknetwork/crypto/tree/main/equality_across_groups)
creates a nice implementation with a very useful proof of concept test code

# Installation and Running the Jupyter Notebooks

In order to run the Jupyter Notebooks, you can choose between:

- [Docker](https://docs.docker.com/desktop/)
- [DevBox](https://www.jetify.com/docs/devbox/installing_devbox/)

If you want to follow the exercises during the hands-on workshop, docker is easier.
However, if you want to develop and send pull requests, it's faster with devbox.

## Docker

Make sure that you have one of the latest versions of [Docker](https://docs.docker.com/desktop/)
installed, and `git` is available, then you can start the jupyter-lab with the following:

```bash
git clone https://github.com/c4dt/how-2025-06-eID
cd how-2025-06-eID
docker compose up
```

Once the docker image is downloaded, you will find an URL like
https://localhost:8888/lab?token=....
Copy/paste this URL to your browser, and off you go!

## Devbox

If you have [DevBox](https://www.jetify.com/docs/devbox/installing_devbox/) installed on your machine
(congrats - I hope you like it as much as I do), you can start the jupyter lab like this:

```bash
git clone https://github.com/c4dt/how-2025-06-eID
cd how-2025-06-eID
devbox run jupyter
```

Once everything is installed, on MacOS it will open the browser directly, on Windows and Linux you need
to search for the URL like
https://localhost:8888/lab?token=....
Copy/paste this URL to your browser, and off you go!

# Directory Structure

In the base directory, you find the two main jupyter notebooks for the afternoon exercises:

- [1-Swiyu](./1-Swiyu.ipynb) which introduces you to the Swiyu test network
- [2-BBS-ECDSA](./2-BBS-ECDSA.ipynb) shows the challenge of using **holder binding** while keeping
the presentations **unlinkable**

In addition to these two files, there is some rust code available here:

[ecdsa_proof](./ecdsa_proof/src/lib.rs)

It wraps the [docknetwork/crypto](https://github.com/docknetwork/crypto/tree/main/equality_across_groups)
proof of concept. 
The main difference is that it uses structures which represent the actors and is geared towards showing
the main challenges and how it works.

# Licensing and Contributing

This code is under an [Apache 2.0 License](./LICENSE.txt).

If you want to contribute, feel free to open an issue or a PR.

You can contact the Factory team of C4DT under [mailto:c4dt-dev@listes.epfl.ch].
