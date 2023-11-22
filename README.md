# Dice Rume

A little chat thing that allows for server rolled dice

To run the client:
`cargo run --features client`

To run the server:
`cargo run --features server`

Various pieces of information in no particular order:
- Currently the server and client only really connect to local host for now <small>soon to be replaced with a config file for the client</small>
- The server listens on port 12346
- The client to server connection uses the noise protocol (`Noise_XXpsk3_25519_ChaChaPoly_SHA256`)
- Room message bodys are encrpyted with a symetric key (XChaCha20)

Things left to do:
- [ ] Pic Messages
- [ ] UI rehaul
- [ ] Map room type
- [ ] Persistent Client Data
- [ ] Vote room type
- [ ] All the bells and whistles
