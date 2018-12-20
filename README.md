# ae_node_helpers
Helper functions for [Aeternity node](https://github.com/aeternity/epoch)'s console

## How to use
Start an Aeternity's node, attach to erlang's console and run
```
{ok, helper_functions, ModBin} = compile:file("PATH_TO_THIS_REPO/helper_functions.erl", [binary]).
code:load_binary(helper_functions, helper_functions, ModBin).
```
Where the `PATH_TO_THIS_REPO` is replaced with the appropriate path.

## Usage

### Decode a key pair

The followin snippet relies on having a `generated_keys` dir in the node's
root dir:
```
{PrivKey, PubKey} = helper_functions:decode_key_pair("generated_keys", <<"Pass1">>).
```

### Spend

```dd
(epoch@localhost)7> TxHash = helper_functions:create_sign_post(spend_tx, [PubKeyFrom, PubKeyTo, _Nonce = 2, _Amount = 123, _Fee = 17000], [PrivKey]).
<<83,147,1,217,11,1,86,51,242,42,108,70,58,190,224,37,52,
  18,213,164,206,126,69,25,88,159,169,13,244,...>>

(epoch@localhost)8> helper_functions:get_tx_state(TxHash).
{ok,#{tx =>
          {signed_tx,{aetx,spend_tx,aec_spend_tx,79,
                           {spend_tx,{id,account,
                                         <<214,238,132,249,132,233,160,228,136,246,92,239,3,91,...>>},
                                     {id,account,
                                         <<214,238,132,249,132,233,160,228,136,246,92,239,3,...>>},
                                     123,17000,0,2,<<>>}},
                     [<<31,49,16,140,128,55,203,188,121,241,27,20,162,111,
                        194,172,106,3,63,238,90,156,...>>]},
      tx_block_hash =>
          <<18,69,201,66,94,161,158,194,0,222,67,146,138,107,152,
            245,52,24,119,233,73,112,49,100,208,...>>}}
```
