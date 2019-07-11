# pchat

pchat is a peer to peer private chat using two key pairs per user: one for the
secure channel (TLS 1.3) and one for the messages content in order to achieve
forward secrecy.

Messages are never stored. Both peers need to be online for the communication
to be possible. Group chat is not implemented. Only short text messages can be
sent.

This is a pet project to learn cryptography, don't use it to communicate real
secrets.

## Build:

    go build

## Generating keys:

To test pchat, generate keys for two users

    ./pchat -i marcelo
    ./pchat -i sonia

## Import contacts:

    mkdir ~/.pchat/contacts/marcelo
    cp ~/.pchat/marcelo.crt ~/.pchat/contacts/marcelo/crt
    cp ~/.pchat/marcelo.pub ~/.pchat/contacts/marcelo/pub
    echo "https://localhost:3008" ~/.pchat/contacts/marcelo/endpoint

    mkdir ~/.pchat/contacts/sonia
    cp ~/.pchat/sonia.crt ~/.pchat/contacts/sonia/crt
    cp ~/.pchat/sonia.pub ~/.pchat/contacts/sonia/pub
    echo "https://localhost:3009" ~/.pchat/contacts/sonia/endpoint

## Chat:

    ./pchat -i marcelo -contact sonia -port 3008
    ./pchat -i sonia -contact marcelo -port 3009
