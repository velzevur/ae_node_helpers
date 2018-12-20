-module(helper_functions).
-export([ decode_key_pair/2
				, create_sign_post/3
        , get_tx_state/1
        , sign_tx/2
        , force_gossip_txs_in_pool/0
        ]).

% Transactions
%% AENS
-export([ preclaim_tx/5
        , preclaim_tx/6
        ]).

%% Spend
-export([ spend_tx/5
        , spend_tx/6
        ]).

%% Channels
-export([ channel_create_tx/9
        , channel_close_mutual_tx/6
        , channel_close_solo_tx/6
        , channel_slash_tx/6
        , channel_settle_tx/6
        , channel_withdraw_tx/7
        , channel_deposit_tx/7
        , channel_snapshot_tx/5
        , channel_force_progress_tx/9
        ]).

decode_key_pair(Dir, Pass) ->
    Decr =
        fun(Enc) ->
            crypto:block_decrypt(aes_ecb, crypto:hash(sha256, Pass), Enc) end,
    {ok, EncPub} = file:read_file(Dir ++ "/key.pub"),
    {ok, EncPriv} = file:read_file(Dir ++ "/key"),
    PrivKey = Decr(EncPriv),
    PubKey = Decr(EncPub),
    %%  validate pair
    SampleMsg = <<"random message">>,
    Signature = enacl:sign_detached(SampleMsg, PrivKey),
    true = {ok, SampleMsg} == enacl:sign_verify_detached(Signature, SampleMsg,
                                                         PubKey),
    {PrivKey, PubKey}.

%% AENS
preclaim_tx(Name, Salt, Owner, Nonce, Fee) ->
    preclaim_tx(Name, Salt, Owner, Nonce, Fee, 0).

preclaim_tx(Name, Salt, Owner, Nonce, Fee, TTL) ->
    {ok, NameAscii} = aens_utils:to_ascii(Name),
    CHash = aens_hash:commitment_hash(NameAscii, Salt),
    TxSpec =
        #{account_id    => aec_id:create(account, Owner),
          nonce         => Nonce,
          commitment_id => aec_id:create(commitment, CHash),
          fee           => Fee,
          ttl           => TTL},
    {ok, _Tx} = aens_preclaim_tx:new(TxSpec).

%% SPEND
spend_tx(From, To, Nonce, Amount, Fee) ->
    spend_tx(From, To, Nonce, Amount, Fee, <<>>).

spend_tx(From, To, Nonce, Amount, Fee, Payload) ->
    TxSpec =
        #{sender_id     => aec_id:create(account, From),
          recipient_id  => aec_id:create(account, To),
          amount        => Amount,
          nonce         => Nonce,
          payload       => Payload,
          fee           => Fee},
    {ok, _Tx} = aec_spend_tx:new(TxSpec).

%% Channels
channel_create_tx(Initiator, InitiatorAmount,
                  Responder, ResponderAmount,
                  ChannelReserve, LockPeriod, Fee,
                  StateHash, Nonce) ->
  TxSpec =
      #{initiator_id       => aec_id:create(account, Initiator),
        initiator_amount   => InitiatorAmount,
        responder_id       => aec_id:create(account, Responder),
        responder_amount   => ResponderAmount,
        channel_reserve    => ChannelReserve,
        lock_period        => LockPeriod,
        fee                => Fee,
        state_hash         => StateHash,
        nonce              => Nonce},
    {ok, _Tx} = aesc_create_tx:new(TxSpec).

channel_close_mutual_tx(Channel, From,
                        InitiatorAmount, ResponderAmount,
                        Fee, Nonce) ->
  TxSpec =
      #{channel_id              => aec_id:create(channel, Channel),
        from_id                 => aec_id:create(account, From),
        initiator_amount_final  => InitiatorAmount,
        responder_amount_final  => ResponderAmount,
        fee                     => Fee,
        nonce                   => Nonce},
    {ok, _Tx} = aesc_close_mutual_tx:new(TxSpec).

channel_close_solo_tx(Channel, From,
                      Payload, PoI,
                      Fee, Nonce) ->
  TxSpec =
      #{channel_id => aec_id:create(channel, Channel),
        from_id    => aec_id:create(account, From),
        payload    => Payload,
        poi        => PoI,
        fee        => Fee,
        nonce      => Nonce},
    {ok, _Tx} = aesc_close_solo_tx:new(TxSpec).

channel_slash_tx(Channel, From,
                      Payload, PoI,
                      Fee, Nonce) ->
  TxSpec =
      #{channel_id => aec_id:create(channel, Channel),
        from_id    => aec_id:create(account, From),
        payload    => Payload,
        poi        => PoI,
        fee        => Fee,
        nonce      => Nonce},
    {ok, _Tx} = aesc_slash_tx:new(TxSpec).

channel_settle_tx(Channel, From,
                  InitiatorAmount, ResponderAmount,
                  Fee, Nonce) ->
  TxSpec =
      #{channel_id => aec_id:create(channel, Channel),
        from_id    => aec_id:create(account, From),
        initiator_amount_final  => InitiatorAmount,
        responder_amount_final  => ResponderAmount,
        fee        => Fee,
        nonce      => Nonce},
    {ok, _Tx} = aesc_settle_tx:new(TxSpec).

channel_withdraw_tx(Channel, To,
                    Amount, StateHash, Round,
                    Fee, Nonce) ->
  TxSpec =
      #{channel_id  => aec_id:create(channel, Channel),
        to_id       => aec_id:create(account, To),
        amount      => Amount,
        state_hash  => StateHash,
        round       => Round,
        fee         => Fee,
        nonce       => Nonce},
    {ok, _Tx} = aesc_withdraw_tx:new(TxSpec).

channel_deposit_tx(Channel, From,
                   Amount, StateHash, Round,
                   Fee, Nonce) ->
  TxSpec =
      #{channel_id  => aec_id:create(channel, Channel),
        from_id     => aec_id:create(account, From),
        amount      => Amount,
        state_hash  => StateHash,
        round       => Round,
        fee         => Fee,
        nonce       => Nonce},
    {ok, _Tx} = aesc_deposit_tx:new(TxSpec).

channel_snapshot_tx(Channel, From,
                    Payload, Fee, Nonce) ->
  TxSpec =
      #{channel_id  => aec_id:create(channel, Channel),
        from_id     => aec_id:create(account, From),
        payload     => Payload,
        fee         => Fee,
        nonce       => Nonce},
    {ok, _Tx} = aesc_snapshot_solo_tx:new(TxSpec).

channel_force_progress_tx(Channel, From,
                          Payload, Update, StateHash, Round, OffChainTrees,
                          Fee, Nonce) ->
  TxSpec =
      #{channel_id      => aec_id:create(channel, Channel),
        from_id         => aec_id:create(account, From),
        payload         => Payload,
        update          => Update,
        state_hash      => StateHash,
        round           => Round,
        offchain_trees  => OffChainTrees,
        fee             => Fee,
        nonce           => Nonce},
    {ok, _Tx} = aesc_force_progress_tx:new(TxSpec).

%% Higher level
create_sign_post(FunName, Args, PrivKeys) ->
    {ok, Tx} = apply(?MODULE, FunName, Args),
    {ok, SignedTx} = sign_tx(Tx, PrivKeys),
    ok = aec_tx_pool:push(SignedTx),
    aetx_sign:hash(SignedTx).

get_tx_state(TxHash) ->
		case aec_chain:find_tx_with_location(TxHash) of
				none ->
						{error, not_found};
				{Tag, Tx} ->
						{ok, #{tx => Tx, tx_block_hash => Tag}}
		end.

%% {ok, SignedTx} = helper_functions:sign_tx(Tx, PrivKey).
sign_tx(UnsignedTx, PrivK)when is_binary(PrivK) ->
    sign_tx(UnsignedTx, [PrivK]);
sign_tx(UnsignedTx, PrivKs) when is_list(PrivKs) ->
    Bin = aetx:serialize_to_binary(UnsignedTx), 
    BinForNetwork = aec_governance:add_network_id(Bin),
    Signatures = [ enacl:sign_detached(BinForNetwork, PrivK) || PrivK <- PrivKs],
    {ok, aetx_sign:new(UnsignedTx, Signatures)}.

force_gossip_txs_in_pool() ->
    [ aec_events:publish(tx_created, Tx)
          || {ok, Txs} <- [aec_tx_pool:peek(30)], Tx <- Txs ],
    ok.

%% {ok, UlfPubkey} = aehttp_api_encoder:safe_decode(account_pubkey, <<"ak_DqPzA1FnQ5TVT6STu6UZy5Grj6cfCm48S3uni9BUp9HipHVNB">>).
%% {ok, Tx} = helper_functions:spend_tx(PubKey, UlfPubkey, 1, 100000, 17000, <<>>).
%% {ok, SignedTx} = helper_functions:sign_tx(Tx, PrivKey).
