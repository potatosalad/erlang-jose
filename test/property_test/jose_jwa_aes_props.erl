%%% % @format
-module(jose_jwa_aes_props).

-include_lib("proper/include/proper.hrl").

% -compile(export_all).

block_size() -> oneof([128, 192, 256]).
cbc_iv() -> binary(16).
gcm_iv() -> binary(12).

cbc_block_encryptor_gen() ->
    ?LET(
        {Bits, IV, PlainText},
        {block_size(), cbc_iv(), binary()},
        {Bits, binary(Bits div 8), IV, jose_jwa_pkcs7:pad(PlainText)}
    ).

ecb_block_encryptor_gen() ->
    ?LET(
        {Bits, PlainText},
        {block_size(), binary()},
        {Bits, binary(Bits div 8), jose_jwa_pkcs7:pad(PlainText)}
    ).

gcm_block_encryptor_gen() ->
    ?LET(
        {Bits, IV, AAD, PlainText},
        {block_size(), gcm_iv(), binary(), binary()},
        {Bits, binary(Bits div 8), IV, AAD, jose_jwa_pkcs7:pad(PlainText)}
    ).

prop_cbc_block_encrypt_and_cbc_block_decrypt() ->
    ?FORALL(
        {Bits, Key, IV, PlainText},
        cbc_block_encryptor_gen(),
        begin
            CipherText = jose_jwa_aes:block_encrypt({aes_cbc, Bits}, Key, IV, PlainText),
            PlainText =:= jose_jwa_aes:block_decrypt({aes_cbc, Bits}, Key, IV, CipherText)
        end
    ).

prop_cbc_block_encrypt_and_jwa_block_decrypt() ->
    ?FORALL(
        {Bits, Key, IV, PlainText},
        cbc_block_encryptor_gen(),
        begin
            Cipher = aes_cbc,
            CipherText = jose_jwa_aes:block_encrypt({Cipher, Bits}, Key, IV, PlainText),
            PlainText =:= jose_jwa:block_decrypt({Cipher, Bits}, Key, IV, CipherText)
        end
    ).

prop_jwa_block_encrypt_and_cbc_block_decrypt() ->
    ?FORALL(
        {Bits, Key, IV, PlainText},
        cbc_block_encryptor_gen(),
        begin
            Cipher = aes_cbc,
            CipherText = jose_jwa:block_encrypt({Cipher, Bits}, Key, IV, PlainText),
            PlainText =:= jose_jwa_aes:block_decrypt({Cipher, Bits}, Key, IV, CipherText)
        end
    ).

prop_jwa_block_encrypt_and_ecb_block_decrypt() ->
    ?FORALL(
        {Bits, Key, PlainText},
        ecb_block_encryptor_gen(),
        begin
            Cipher = aes_ecb,
            CipherText = <<
                <<(jose_jwa:block_encrypt({Cipher, Bits}, Key, Block))/binary>>
             || <<Block:16/binary>> <= PlainText
            >>,
            PlainText =:= jose_jwa_aes:block_decrypt({aes_ecb, Bits}, Key, CipherText)
        end
    ).

prop_jwa_block_encrypt_and_gcm_block_decrypt() ->
    ?FORALL(
        {Bits, Key, IV, AAD, PlainText},
        gcm_block_encryptor_gen(),
        begin
            Cipher = aes_gcm,
            {CipherText, CipherTag} = jose_jwa:block_encrypt({Cipher, Bits}, Key, IV, {AAD, PlainText}),
            PlainText =:= jose_jwa_aes:block_decrypt({aes_gcm, Bits}, Key, IV, {AAD, CipherText, CipherTag})
        end
    ).

prop_ecb_block_encrypt_and_ecb_block_decrypt() ->
    ?FORALL(
        {Bits, Key, PlainText},
        ecb_block_encryptor_gen(),
        begin
            CipherText = jose_jwa_aes:block_encrypt({aes_ecb, Bits}, Key, PlainText),
            PlainText =:= jose_jwa_aes:block_decrypt({aes_ecb, Bits}, Key, CipherText)
        end
    ).

prop_ecb_block_encrypt_and_jwa_block_decrypt() ->
    ?FORALL(
        {Bits, Key, PlainText},
        ecb_block_encryptor_gen(),
        begin
            CipherText = jose_jwa_aes:block_encrypt({aes_ecb, Bits}, Key, PlainText),
            Cipher = aes_ecb,
            PlainText =:=
                <<<<(jose_jwa:block_decrypt({Cipher, Bits}, Key, Block))/binary>> || <<Block:16/binary>> <= CipherText>>
        end
    ).

prop_gcm_block_encrypt_and_gcm_block_decrypt() ->
    ?FORALL(
        {Bits, Key, IV, AAD, PlainText},
        gcm_block_encryptor_gen(),
        begin
            {CipherText, CipherTag} = jose_jwa_aes:block_encrypt({aes_gcm, Bits}, Key, IV, {AAD, PlainText}),
            PlainText =:= jose_jwa_aes:block_decrypt({aes_gcm, Bits}, Key, IV, {AAD, CipherText, CipherTag})
        end
    ).

prop_gcm_block_encrypt_and_jwa_block_decrypt() ->
    ?FORALL(
        {Bits, Key, IV, AAD, PlainText},
        gcm_block_encryptor_gen(),
        begin
            {CipherText, CipherTag} = jose_jwa_aes:block_encrypt({aes_gcm, Bits}, Key, IV, {AAD, PlainText}),
            Cipher = aes_gcm,
            PlainText =:= jose_jwa:block_decrypt({Cipher, Bits}, Key, IV, {AAD, CipherText, CipherTag})
        end
    ).
