%%% % @format
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <andrew@pixid.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc
%%% @end
%%% Created :  08 Aug 2016 by Andrew Bennett <andrew@pixid.com>
%%%-------------------------------------------------------------------
-module(jose_jwa_chacha20_poly1305_SUITE).

-include_lib("common_test/include/ct.hrl").

-include("jose.hrl").

%% ct.
-export([all/0]).
-export([groups/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_group/2]).
-export([end_per_group/2]).

%% Tests.
-export([aead/0]).
-export([aead/1]).
-export([block/0]).
-export([block/1]).
-export([encrypt/0]).
-export([encrypt/1]).
-export([key/0]).
-export([key/1]).
-export([mac/0]).
-export([mac/1]).

all() ->
    [
        {group, chacha20},
        {group, chacha20_poly1305},
        {group, poly1305}
    ].

groups() ->
    [
        {chacha20, [parallel], [
            block,
            encrypt
        ]},
        {chacha20_poly1305, [parallel], [
            aead
        ]},
        {poly1305, [parallel], [
            key,
            mac
        ]}
    ].

init_per_suite(Config) ->
    application:set_env(jose, crypto_fallback, true),
    application:set_env(jose, unsecured_signing, true),
    _ = application:ensure_all_started(jose),
    Config.

end_per_suite(_Config) ->
    _ = application:stop(jose),
    ok.

init_per_group(Group, Config) ->
    jose_ct:start(Group, group_config(Group, Config)).

end_per_group(_Group, Config) ->
    jose_ct:stop(Config),
    ok.

%%====================================================================
%% Tests
%%====================================================================

aead() ->
    [{doc, "Test ChaCha20/Poly1305 AEAD function"}].
aead(Config) when is_list(Config) ->
    AEADs = lazy_eval(proplists:get_value(aead, Config)),
    lists:foreach(fun aead_cipher/1, AEADs).

block() ->
    [{doc, "Test ChaCha20 Block function"}].
block(Config) when is_list(Config) ->
    Blocks = lazy_eval(proplists:get_value(block, Config)),
    lists:foreach(fun chacha20_block/1, Blocks).

encrypt() ->
    [{doc, "Test ChaCha20 Encryption function"}].
encrypt(Config) when is_list(Config) ->
    Encrypts = lazy_eval(proplists:get_value(encrypt, Config)),
    lists:foreach(fun chacha20_encrypt/1, Encrypts).

key() ->
    [{doc, "Test Poly1305 Key Generation function"}].
key(Config) when is_list(Config) ->
    Keys = lazy_eval(proplists:get_value(key, Config)),
    lists:foreach(fun poly1305_key/1, Keys).

mac() ->
    [{doc, "Test Poly1305 MAC function"}].
mac(Config) when is_list(Config) ->
    MACs = lazy_eval(proplists:get_value(mac, Config)),
    lists:foreach(fun poly1305_mac/1, MACs).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
aead_cipher({Key, PlainText, IV, AAD, CipherText, CipherTag}) ->
    case jose_jwa_chacha20_poly1305:encrypt(PlainText, AAD, IV, Key) of
        {CipherText, CipherTag} ->
            ok;
        Other0 ->
            ct:fail({
                {jose_jwa_chacha20_poly1305, encrypt, [PlainText, AAD, IV, Key]},
                {expected, {CipherText, CipherTag}},
                {got, Other0}
            })
    end,
    case jose_jwa_chacha20_poly1305:decrypt(CipherText, CipherTag, AAD, IV, Key) of
        PlainText ->
            ok;
        Other1 ->
            ct:fail({
                {jose_jwa_chacha20_poly1305, decrypt, [CipherText, CipherTag, AAD, IV, Key]},
                {expected, PlainText},
                {got, Other1}
            })
    end.

%% @private
chacha20_block({Key, Nonce, Counter, State}) ->
    case jose_jwa_chacha20:block(Key, Counter, Nonce) of
        State ->
            ok;
        Other0 ->
            ct:fail({{jose_jwa_chacha20, block, [Key, Counter, Nonce]}, {expected, State}, {got, Other0}})
    end.

%% @private
chacha20_encrypt({Key, Nonce, Counter, PlainText, CipherText}) ->
    case jose_jwa_chacha20:encrypt(Key, Counter, Nonce, PlainText) of
        CipherText ->
            ok;
        Other0 ->
            ct:fail({
                {jose_jwa_chacha20, encrypt, [Key, Counter, Nonce, PlainText]}, {expected, CipherText}, {got, Other0}
            })
    end,
    case jose_jwa_chacha20:encrypt(Key, Counter, Nonce, CipherText) of
        PlainText ->
            ok;
        Other1 ->
            ct:fail({
                {jose_jwa_chacha20, encrypt, [Key, Counter, Nonce, CipherText]}, {expected, PlainText}, {got, Other1}
            })
    end.

%% @private
poly1305_key({Key, Nonce, OneTimeKey}) ->
    case jose_jwa_chacha20_poly1305:poly1305_key_gen(Key, Nonce) of
        OneTimeKey ->
            ok;
        Other0 ->
            ct:fail({
                {jose_jwa_chacha20_poly1305, poly1305_key_gen, [Key, Nonce]}, {expected, OneTimeKey}, {got, Other0}
            })
    end.

%% @private
poly1305_mac({OneTimeKey, Text, Tag}) ->
    case jose_jwa_poly1305:mac(Text, OneTimeKey) of
        Tag ->
            ok;
        Other0 ->
            ct:fail({{jose_jwa_poly1305, mac, [Text, OneTimeKey]}, {expected, Tag}, {got, Other0}})
    end.

%% @private
group_config(chacha20, Config) ->
    Block = chacha20_block(),
    Encrypt = chacha20_encrypt(),
    [{block, Block}, {encrypt, Encrypt} | Config];
group_config(chacha20_poly1305, Config) ->
    AEAD = chacha20_poly1305(),
    [{aead, AEAD} | Config];
group_config(poly1305, Config) ->
    Key = poly1305_key(),
    MAC = poly1305_mac(),
    [{key, Key}, {mac, MAC} | Config].

%% @private
hexstr2bin(S) ->
    list_to_binary(hexstr2list(S)).

%% @private
hexstr2list([X, Y | T]) ->
    [mkint(X) * 16 + mkint(Y) | hexstr2list(T)];
hexstr2list([]) ->
    [].

%% @private
hexts(TS) ->
    [
        begin
            list_to_tuple([
                begin
                    case V of
                        _ when is_list(V) ->
                            hexstr2bin(V);
                        _ ->
                            V
                    end
                end
             || V <- tuple_to_list(T)
            ])
        end
     || T <- TS
    ].

%% Building huge terms (like long_msg/0) in init_per_group seems to cause
%% test_server crash with 'no_answer_from_tc_supervisor' sometimes on some
%% machines. Therefore lazy evaluation when test case has started.
lazy_eval(F) when is_function(F) -> F();
lazy_eval(Lst) when is_list(Lst) -> lists:map(fun lazy_eval/1, Lst);
lazy_eval(Tpl) when is_tuple(Tpl) -> list_to_tuple(lists:map(fun lazy_eval/1, tuple_to_list(Tpl)));
lazy_eval(Term) -> Term.

%% @private
mkint(C) when $0 =< C, C =< $9 ->
    C - $0;
mkint(C) when $A =< C, C =< $F ->
    C - $A + 10;
mkint(C) when $a =< C, C =< $f ->
    C - $a + 10.

%% ChaCha20 Block test vectors from:
%% https://tools.ietf.org/html/rfc7539#appendix-A.1
chacha20_block() ->
    hexts([
        % Test Vector #1
        {
            %% Key
            "00000000000000000000000000000000"
            "00000000000000000000000000000000",
            %% Nonce
            "000000000000000000000000",
            %% Block Counter
            0,
            %% State
            "76b8e0ada0f13d90405d6ae55386bd28"
            "bdd219b8a08ded1aa836efcc8b770dc7"
            "da41597c5157488d7724e03fb8d84a37"
            "6a43b8f41518a11cc387b669b2ee6586"
        },
        % Test Vector #2
        {
            %% Key
            "00000000000000000000000000000000"
            "00000000000000000000000000000000",
            %% Nonce
            "000000000000000000000000",
            %% Block Counter
            1,
            %% State
            "9f07e7be5551387a98ba977c732d080d"
            "cb0f29a048e3656912c6533e32ee7aed"
            "29b721769ce64e43d57133b074d839d5"
            "31ed1f28510afb45ace10a1f4b794d6f"
        },
        % Test Vector #3
        {
            %% Key
            "00000000000000000000000000000000"
            "00000000000000000000000000000001",
            %% Nonce
            "000000000000000000000000",
            %% Block Counter
            1,
            %% State
            "3aeb5224ecf849929b9d828db1ced4dd"
            "832025e8018b8160b82284f3c949aa5a"
            "8eca00bbb4a73bdad192b5c42f73f2fd"
            "4e273644c8b36125a64addeb006c13a0"
        },
        % Test Vector #4
        {
            %% Key
            "00ff0000000000000000000000000000"
            "00000000000000000000000000000000",
            %% Nonce
            "000000000000000000000000",
            %% Block Counter
            2,
            %% State
            "72d54dfbf12ec44b362692df94137f32"
            "8fea8da73990265ec1bbbea1ae9af0ca"
            "13b25aa26cb4a648cb9b9d1be65b2c09"
            "24a66c54d545ec1b7374f4872e99f096"
        },
        % Test Vector #5
        {
            %% Key
            "00000000000000000000000000000000"
            "00000000000000000000000000000000",
            %% Nonce
            "000000000000000000000002",
            %% Block Counter
            0,
            %% State
            "c2c64d378cd536374ae204b9ef933fcd"
            "1a8b2288b3dfa49672ab765b54ee27c7"
            "8a970e0e955c14f3a88e741b97c286f7"
            "5f8fc299e8148362fa198a39531bed6d"
        }
    ]).

%% ChaCha20 Encryption test vectors from:
%% https://tools.ietf.org/html/rfc7539#appendix-A.2
chacha20_encrypt() ->
    hexts([
        % Test Vector #1
        {
            %% Key
            "00000000000000000000000000000000"
            "00000000000000000000000000000000",
            %% Nonce
            "000000000000000000000000",
            %% Block Counter
            0,
            %% PlainText
            "00000000000000000000000000000000"
            "00000000000000000000000000000000"
            "00000000000000000000000000000000"
            "00000000000000000000000000000000",
            %% CipherText
            "76b8e0ada0f13d90405d6ae55386bd28"
            "bdd219b8a08ded1aa836efcc8b770dc7"
            "da41597c5157488d7724e03fb8d84a37"
            "6a43b8f41518a11cc387b669b2ee6586"
        },
        % Test Vector #2
        {
            %% Key
            "00000000000000000000000000000000"
            "00000000000000000000000000000001",
            %% Nonce
            "000000000000000000000002",
            %% Block Counter
            1,
            %% PlainText
            "416e79207375626d697373696f6e2074"
            "6f20746865204945544620696e74656e"
            "6465642062792074686520436f6e7472"
            "696275746f7220666f72207075626c69"
            "636174696f6e20617320616c6c206f72"
            "2070617274206f6620616e2049455446"
            "20496e7465726e65742d447261667420"
            "6f722052464320616e6420616e792073"
            "746174656d656e74206d616465207769"
            "7468696e2074686520636f6e74657874"
            "206f6620616e20494554462061637469"
            "7669747920697320636f6e7369646572"
            "656420616e20224945544620436f6e74"
            "7269627574696f6e222e205375636820"
            "73746174656d656e747320696e636c75"
            "6465206f72616c2073746174656d656e"
            "747320696e2049455446207365737369"
            "6f6e732c2061732077656c6c20617320"
            "7772697474656e20616e6420656c6563"
            "74726f6e696320636f6d6d756e696361"
            "74696f6e73206d61646520617420616e"
            "792074696d65206f7220706c6163652c"
            "20776869636820617265206164647265"
            "7373656420746f",
            %% CipherText
            "a3fbf07df3fa2fde4f376ca23e827370"
            "41605d9f4f4f57bd8cff2c1d4b7955ec"
            "2a97948bd3722915c8f3d337f7d37005"
            "0e9e96d647b7c39f56e031ca5eb6250d"
            "4042e02785ececfa4b4bb5e8ead0440e"
            "20b6e8db09d881a7c6132f420e527950"
            "42bdfa7773d8a9051447b3291ce1411c"
            "680465552aa6c405b7764d5e87bea85a"
            "d00f8449ed8f72d0d662ab052691ca66"
            "424bc86d2df80ea41f43abf937d3259d"
            "c4b2d0dfb48a6c9139ddd7f76966e928"
            "e635553ba76c5c879d7b35d49eb2e62b"
            "0871cdac638939e25e8a1e0ef9d5280f"
            "a8ca328b351c3c765989cbcf3daa8b6c"
            "cc3aaf9f3979c92b3720fc88dc95ed84"
            "a1be059c6499b9fda236e7e818b04b0b"
            "c39c1e876b193bfe5569753f88128cc0"
            "8aaa9b63d1a16f80ef2554d7189c411f"
            "5869ca52c5b83fa36ff216b9c1d30062"
            "bebcfd2dc5bce0911934fda79a86f6e6"
            "98ced759c3ff9b6477338f3da4f9cd85"
            "14ea9982ccafb341b2384dd902f3d1ab"
            "7ac61dd29c6f21ba5b862f3730e37cfd"
            "c4fd806c22f221"
        },
        % Test Vector #3
        {
            %% Key
            "1c9240a5eb55d38af333888604f6b5f0"
            "473917c1402b80099dca5cbc207075c0",
            %% Nonce
            "000000000000000000000002",
            %% Block Counter
            42,
            %% PlainText
            "2754776173206272696c6c69672c2061"
            "6e642074686520736c6974687920746f"
            "7665730a446964206779726520616e64"
            "2067696d626c6520696e207468652077"
            "6162653a0a416c6c206d696d73792077"
            "6572652074686520626f726f676f7665"
            "732c0a416e6420746865206d6f6d6520"
            "7261746873206f757467726162652e",
            %% CipherText
            "62e6347f95ed87a45ffae7426f27a1df"
            "5fb69110044c0d73118effa95b01e5cf"
            "166d3df2d721caf9b21e5fb14c616871"
            "fd84c54f9d65b283196c7fe4f60553eb"
            "f39c6402c42234e32a356b3e764312a6"
            "1a5532055716ead6962568f87d3f3f77"
            "04c6a8d1bcd1bf4d50d6154b6da731b1"
            "87b58dfd728afa36757a797ac188d1"
        }
    ]).

%% ChaCha20/Poly1305 AEAD test vectors from:
%% https://tools.ietf.org/html/rfc7539#section-2.8.2
%% https://tools.ietf.org/html/rfc7539#appendix-A.5
chacha20_poly1305() ->
    hexts([
        {
            %% Key
            "808182838485868788898a8b8c8d8e8f"
            "909192939495969798999a9b9c9d9e9f",
            %% PlainText
            "4c616469657320616e642047656e746c"
            "656d656e206f662074686520636c6173"
            "73206f66202739393a20496620492063"
            "6f756c64206f6666657220796f75206f"
            "6e6c79206f6e652074697020666f7220"
            "746865206675747572652c2073756e73"
            "637265656e20776f756c642062652069"
            "742e",
            %% IV
            "070000004041424344454647",
            %% AAD
            "50515253c0c1c2c3c4c5c6c7",
            %% CipherText
            "d31a8d34648e60db7b86afbc53ef7ec2"
            "a4aded51296e08fea9e2b5a736ee62d6"
            "3dbea45e8ca9671282fafb69da92728b"
            "1a71de0a9e060b2905d6a5b67ecd3b36"
            "92ddbd7f2d778b8c9803aee328091b58"
            "fab324e4fad675945585808b4831d7bc"
            "3ff4def08e4b7a9de576d26586cec64b"
            "6116",
            %% CipherTag
            "1ae10b594f09e26a7e902ecbd0600691"
        },
        {
            %% Key
            "1c9240a5eb55d38af333888604f6b5f0"
            "473917c1402b80099dca5cbc207075c0",
            %% PlainText
            "496e7465726e65742d44726166747320"
            "61726520647261667420646f63756d65"
            "6e74732076616c696420666f72206120"
            "6d6178696d756d206f6620736978206d"
            "6f6e74687320616e64206d6179206265"
            "20757064617465642c207265706c6163"
            "65642c206f72206f62736f6c65746564"
            "206279206f7468657220646f63756d65"
            "6e747320617420616e792074696d652e"
            "20497420697320696e617070726f7072"
            "6961746520746f2075736520496e7465"
            "726e65742d4472616674732061732072"
            "65666572656e6365206d617465726961"
            "6c206f7220746f206369746520746865"
            "6d206f74686572207468616e20617320"
            "2fe2809c776f726b20696e2070726f67"
            "726573732e2fe2809d",
            %% IV
            "000000000102030405060708",
            %% AAD
            "f33388860000000000004e91",
            %% CipherText
            "64a0861575861af460f062c79be643bd"
            "5e805cfd345cf389f108670ac76c8cb2"
            "4c6cfc18755d43eea09ee94e382d26b0"
            "bdb7b73c321b0100d4f03b7f355894cf"
            "332f830e710b97ce98c8a84abd0b9481"
            "14ad176e008d33bd60f982b1ff37c855"
            "9797a06ef4f0ef61c186324e2b350638"
            "3606907b6a7c02b0f9f6157b53c867e4"
            "b9166c767b804d46a59b5216cde7a4e9"
            "9040c5a40433225ee282a1b0a06c523e"
            "af4534d7f83fa1155b0047718cbc546a"
            "0d072b04b3564eea1b422273f548271a"
            "0bb2316053fa76991955ebd63159434e"
            "cebb4e466dae5a1073a6727627097a10"
            "49e617d91d361094fa68f0ff77987130"
            "305beaba2eda04df997b714d6c6f2c29"
            "a6ad5cb4022b02709b",
            %% CipherTag
            "eead9d67890cbb22392336fea1851f38"
        }
    ]).

%% Poly1305 Key Generation test vectors from:
%% https://tools.ietf.org/html/rfc7539#appendix-A.4
poly1305_key() ->
    hexts([
        % Test Vector #1
        {
            %% Key
            "00000000000000000000000000000000"
            "00000000000000000000000000000000",
            %% Nonce
            "000000000000000000000000",
            %% One-Time Key
            "76b8e0ada0f13d90405d6ae55386bd28"
            "bdd219b8a08ded1aa836efcc8b770dc7"
        },
        % Test Vector #2
        {
            %% Key
            "00000000000000000000000000000000"
            "00000000000000000000000000000001",
            %% Nonce
            "000000000000000000000002",
            %% One-Time Key
            "ecfa254f845f647473d3cb140da9e876"
            "06cb33066c447b87bc2666dde3fbb739"
        },
        % Test Vector #3
        {
            %% Key
            "1c9240a5eb55d38af333888604f6b5f0"
            "473917c1402b80099dca5cbc207075c0",
            %% Nonce
            "000000000000000000000002",
            %% One-Time Key
            "965e3bc6f9ec7ed9560808f4d229f94b"
            "137ff275ca9b3fcbdd59deaad23310ae"
        }
    ]).

%% Poly1305 MAC test vectors from:
%% https://tools.ietf.org/html/rfc7539#appendix-A.3
poly1305_mac() ->
    hexts([
        % Test Vector #1
        {
            %% One-Time Key
            "00000000000000000000000000000000"
            "00000000000000000000000000000000",
            %% Text
            "00000000000000000000000000000000"
            "00000000000000000000000000000000"
            "00000000000000000000000000000000"
            "00000000000000000000000000000000",
            %% Tag
            "00000000000000000000000000000000"
        },
        % Test Vector #2
        {
            %% One-Time Key
            "00000000000000000000000000000000"
            "36e5f6b5c5e06070f0efca96227a863e",
            %% Text
            "416e79207375626d697373696f6e2074"
            "6f20746865204945544620696e74656e"
            "6465642062792074686520436f6e7472"
            "696275746f7220666f72207075626c69"
            "636174696f6e20617320616c6c206f72"
            "2070617274206f6620616e2049455446"
            "20496e7465726e65742d447261667420"
            "6f722052464320616e6420616e792073"
            "746174656d656e74206d616465207769"
            "7468696e2074686520636f6e74657874"
            "206f6620616e20494554462061637469"
            "7669747920697320636f6e7369646572"
            "656420616e20224945544620436f6e74"
            "7269627574696f6e222e205375636820"
            "73746174656d656e747320696e636c75"
            "6465206f72616c2073746174656d656e"
            "747320696e2049455446207365737369"
            "6f6e732c2061732077656c6c20617320"
            "7772697474656e20616e6420656c6563"
            "74726f6e696320636f6d6d756e696361"
            "74696f6e73206d61646520617420616e"
            "792074696d65206f7220706c6163652c"
            "20776869636820617265206164647265"
            "7373656420746f",
            %% Tag
            "36e5f6b5c5e06070f0efca96227a863e"
        },
        % Test Vector #3
        {
            %% One-Time Key
            "36e5f6b5c5e06070f0efca96227a863e"
            "00000000000000000000000000000000",
            %% Text
            "416e79207375626d697373696f6e2074"
            "6f20746865204945544620696e74656e"
            "6465642062792074686520436f6e7472"
            "696275746f7220666f72207075626c69"
            "636174696f6e20617320616c6c206f72"
            "2070617274206f6620616e2049455446"
            "20496e7465726e65742d447261667420"
            "6f722052464320616e6420616e792073"
            "746174656d656e74206d616465207769"
            "7468696e2074686520636f6e74657874"
            "206f6620616e20494554462061637469"
            "7669747920697320636f6e7369646572"
            "656420616e20224945544620436f6e74"
            "7269627574696f6e222e205375636820"
            "73746174656d656e747320696e636c75"
            "6465206f72616c2073746174656d656e"
            "747320696e2049455446207365737369"
            "6f6e732c2061732077656c6c20617320"
            "7772697474656e20616e6420656c6563"
            "74726f6e696320636f6d6d756e696361"
            "74696f6e73206d61646520617420616e"
            "792074696d65206f7220706c6163652c"
            "20776869636820617265206164647265"
            "7373656420746f",
            %% Tag
            "f3477e7cd95417af89a6b8794c310cf0"
        },
        % Test Vector #4
        {
            %% One-Time Key
            "1c9240a5eb55d38af333888604f6b5f0"
            "473917c1402b80099dca5cbc207075c0",
            %% Text
            "2754776173206272696c6c69672c2061"
            "6e642074686520736c6974687920746f"
            "7665730a446964206779726520616e64"
            "2067696d626c6520696e207468652077"
            "6162653a0a416c6c206d696d73792077"
            "6572652074686520626f726f676f7665"
            "732c0a416e6420746865206d6f6d6520"
            "7261746873206f757467726162652e",
            %% Tag
            "4541669a7eaaee61e708dc7cbcc5eb62"
        },
        % Test Vector #5
        {
            %% One-Time Key
            "02000000000000000000000000000000"
            "00000000000000000000000000000000",
            %% Text
            "ffffffffffffffffffffffffffffffff",
            %% Tag
            "03000000000000000000000000000000"
        },
        % Test Vector #6
        {
            %% One-Time Key
            "02000000000000000000000000000000"
            "ffffffffffffffffffffffffffffffff",
            %% Text
            "02000000000000000000000000000000",
            %% Tag
            "03000000000000000000000000000000"
        },
        % Test Vector #7
        {
            %% One-Time Key
            "01000000000000000000000000000000"
            "00000000000000000000000000000000",
            %% Text
            "ffffffffffffffffffffffffffffffff"
            "f0ffffffffffffffffffffffffffffff"
            "11000000000000000000000000000000",
            %% Tag
            "05000000000000000000000000000000"
        },
        % Test Vector #8
        {
            %% One-Time Key
            "01000000000000000000000000000000"
            "00000000000000000000000000000000",
            %% Text
            "ffffffffffffffffffffffffffffffff"
            "fbfefefefefefefefefefefefefefefe"
            "01010101010101010101010101010101",
            %% Tag
            "00000000000000000000000000000000"
        },
        % Test Vector #9
        {
            %% One-Time Key
            "02000000000000000000000000000000"
            "00000000000000000000000000000000",
            %% Text
            "fdffffffffffffffffffffffffffffff",
            %% Tag
            "faffffffffffffffffffffffffffffff"
        },
        % Test Vector #10
        {
            %% One-Time Key
            "01000000000000000400000000000000"
            "00000000000000000000000000000000",
            %% Text
            "e33594d7505e43b90000000000000000"
            "3394d7505e4379cd0100000000000000"
            "00000000000000000000000000000000"
            "01000000000000000000000000000000",
            %% Tag
            "14000000000000005500000000000000"
        },
        % Test Vector #11
        {
            %% One-Time Key
            "01000000000000000400000000000000"
            "00000000000000000000000000000000",
            %% Text
            "e33594d7505e43b90000000000000000"
            "3394d7505e4379cd0100000000000000"
            "00000000000000000000000000000000",
            %% Tag
            "13000000000000000000000000000000"
        }
    ]).
