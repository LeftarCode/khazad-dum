# Khazad-dûm
>In the fictional world of J. R. R. Tolkien, Moria, also named Khazad-dûm, is an ancient subterranean complex in Middle-earth, comprising a vast labyrinthine network of tunnels, chambers, mines and halls under the Misty Mountains, with doors on both the western and the eastern sides of the mountain range. In much of Middle-earth's fictional history, Moria was the greatest city of the Dwarves. The city's wealth was founded on its mines, which produced mithril, a fictional metal of great beauty and strength, suitable for armour.
~ Wikipedia

# Description
Khazad-dûm is a powerful library inspired by the legendary city of Middle-earth. It provides unrivaled protection for your application secrets, just as Mithril, the precious metal of great value and strength.

With Khazad-dûm, you can confidently manage and store your secrets, ensuring their utmost confidentiality and integrity. Leveraging the TPM2 module, this library offers a robust and tamper-resistant environment for secure secret storage and retrieval.

## Build
- Generate project
```
cmake -S . -B build
```
- Build project
```
cmake --build build --config Release
cmake --build build --config Debug
```

## Usage
- Create sealing policy (on target machine):
```
./khazad-dum create_policy <filename>.json
```
- Create private key (on your machine, using OpenSSL):
```
openssl ecparam -name prime256v1 -genkey -noout -out privkey.pem
```
- Encrypt secrets (on your machine):
```
./khazad-dum encrypt_secrets <policy>.json <secrets>.json <privkey>.pem
```

### Secrets format
Below you can find example secret input:
```
{
    "secrets": {
        "DB_USERNAME": "username",
        "DB_PASSWORD": "password"
    }
}
```