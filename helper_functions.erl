-module(helper_functions).
-export([ decode_key_pair/2
				, create_sign_post/3
        , get_tx_state/1
        , sign_tx/2
        , force_gossip_txs_in_pool/0
        ]).

% Transactions
%% AENS
-export([ preclaim_tx/3
        , preclaim_tx/4
        ]).

%% Spend
-export([ spend_tx/3
        , spend_tx/4
        ]).

%% Channels
-export([ channel_create_tx/7
        , channel_close_mutual_tx/4
        , channel_close_solo_tx/6
        , channel_slash_tx/6
        , channel_settle_tx/4
        , channel_withdraw_tx/5
        , channel_deposit_tx/5
        , channel_snapshot_tx/6
        , channel_force_progress_tx/7
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
preclaim_tx(Name, Salt, Owner) ->
    preclaim_tx(Name, Salt, Owner, 0).

preclaim_tx(Name, Salt, Owner, TTL) ->
    {ok, NameAscii} = aens_utils:to_ascii(Name),
    CHash = aens_hash:commitment_hash(NameAscii, Salt),
    TxSpec =
        #{account_id    => aec_id:create(account, Owner),
          nonce         => next_nonce(Owner),
          commitment_id => aec_id:create(commitment, CHash),
          ttl           => TTL},
    {ok, _Tx} = tx_with_minimal_fee(TxSpec, aens_preclaim_tx).

%% SPEND
spend_tx(From, To, Amount) ->
    spend_tx(From, To, Amount, <<>>).

spend_tx(From, To, Amount, Payload) ->
    TxSpec =
        #{sender_id     => aec_id:create(account, From),
          recipient_id  => aec_id:create(account, To),
          amount        => Amount,
          nonce         => next_nonce(From),
          payload       => Payload},
    {ok, _Tx} = tx_with_minimal_fee(TxSpec, aec_spend_tx).

%% Channels
channel_create_tx(Initiator, InitiatorAmount,
                  Responder, ResponderAmount,
                  ChannelReserve, LockPeriod,
                  StateHash) ->
    TxSpec =
        #{initiator_id       => aec_id:create(account, Initiator),
          initiator_amount   => InitiatorAmount,
          responder_id       => aec_id:create(account, Responder),
          responder_amount   => ResponderAmount,
          channel_reserve    => ChannelReserve,
          lock_period        => LockPeriod,
          state_hash         => StateHash,
          nonce         => next_nonce(Initiator)},
    {ok, _Tx} = tx_with_minimal_fee(TxSpec, aesc_create_tx).

channel_close_mutual_tx(Channel, From, InitiatorAmount, ResponderAmount) ->
    TxSpec =
        #{channel_id              => aec_id:create(channel, Channel),
          from_id                 => aec_id:create(account, From),
          initiator_amount_final  => InitiatorAmount,
          responder_amount_final  => ResponderAmount,
          nonce         => next_nonce(From)},
    {ok, _Tx} = tx_with_minimal_fee(TxSpec, aesc_close_mutual_tx).

channel_close_solo_tx(ChannelPubkey, From, IAmt, RAmt, Round, BothPrivkeys) ->
    {PoI, Payload} = poi_and_payload(ChannelPubkey, IAmt, RAmt, Round,
                                     BothPrivkeys),
    TxSpec =
        #{channel_id => aec_id:create(channel, ChannelPubkey),
          from_id    => aec_id:create(account, From),
          payload    => Payload,
          poi        => PoI,
          nonce      => next_nonce(From)},
    {ok, _Tx} = tx_with_minimal_fee(TxSpec, aesc_close_solo_tx).

channel_slash_tx(ChannelPubkey, From, IAmt, RAmt, Round, BothPrivkeys) ->
    {PoI, Payload} = poi_and_payload(ChannelPubkey, IAmt, RAmt, Round,
                                     BothPrivkeys),
    TxSpec =
        #{channel_id => aec_id:create(channel, ChannelPubkey),
          from_id    => aec_id:create(account, From),
          payload    => Payload,
          poi        => PoI,
          nonce      => 19},% next_nonce(From)},
    {ok, _Tx} = tx_with_minimal_fee(TxSpec, aesc_slash_tx).

channel_settle_tx(Channel, From, InitiatorAmount, ResponderAmount) ->
    TxSpec =
        #{channel_id => aec_id:create(channel, Channel),
          from_id    => aec_id:create(account, From),
          initiator_amount_final  => InitiatorAmount,
          responder_amount_final  => ResponderAmount,
          nonce      => next_nonce(From)},
    {ok, _Tx} = tx_with_minimal_fee(TxSpec, aesc_settle_tx).

channel_withdraw_tx(Channel, To, Amount, StateHash, Round) ->
    TxSpec =
        #{channel_id  => aec_id:create(channel, Channel),
          to_id       => aec_id:create(account, To),
          amount      => Amount,
          state_hash  => StateHash,
          round       => Round,
          nonce      => next_nonce(To)},
    {ok, _Tx} = tx_with_minimal_fee(TxSpec, aesc_withdraw_tx).

channel_deposit_tx(Channel, From,Amount, StateHash, Round) ->
    TxSpec =
        #{channel_id  => aec_id:create(channel, Channel),
          from_id     => aec_id:create(account, From),
          amount      => Amount,
          state_hash  => StateHash,
          round       => Round,
          nonce       => next_nonce(From)},
    {ok, _Tx} = tx_with_minimal_fee(TxSpec, aesc_deposit_tx).

channel_snapshot_tx(Channel, From, Updates, OldHash, OldRound, BothPrivkeys) ->
    TxSpec =
        #{channel_id  => aec_id:create(channel, Channel),
          from_id     => aec_id:create(account, From),
          payload     => off_chain_payload(aec_id:create(channel, Channel),
                                          Updates, OldHash,
                                          OldRound, BothPrivkeys),
          nonce       => next_nonce(From)},
    {ok, _Tx} = tx_with_minimal_fee(TxSpec, aesc_snapshot_solo_tx).

channel_force_progress_tx(Channel, From, Payload, Update, StateHash,
                          Round, OffChainTrees) ->
    TxSpec =
        #{channel_id      => aec_id:create(channel, Channel),
          from_id         => aec_id:create(account, From),
          payload         => Payload,
          update          => Update,
          state_hash      => StateHash,
          round           => Round,
          offchain_trees  => OffChainTrees,
          nonce           => next_nonce(From)},
    {ok, _Tx} = tx_with_minimal_fee(TxSpec, aesc_force_progress_tx).

make_channel_force_progress_tx(ChannelPubkey, From, FromPrivkey,
                               BothPrivkeys, IAmt, RAmt,
                               ContractPubkey,
                               ContractsAndBalances,
                               CallData,
                               Round) ->
    ChannelId = aec_id:create(channel, ChannelPubkey),
    Channel = get_channel(ChannelPubkey),
    Initiator = aesc_channels:initiator_pubkey(Channel),
    Responder = aesc_channels:responder_pubkey(Channel),
    Reserve   = aesc_channels:channel_reserve(Channel),
    Contracts = [C || {C, _Amt} <- ContractsAndBalances],
    ContractBalances =
        lists:map(
            fun({Contract, Amt}) ->
                Pubkey = aect_contracts:pubkey(Contract),
                {Pubkey, Amt}
            end,
            ContractsAndBalances),
    OffChainTrees =
        create_offchain_trees([{Initiator, IAmt}, {Responder, RAmt}]
                                  ++ ContractBalances,
                              Contracts),
    Payload = off_chain_payload(ChannelId, [], aec_trees:hash(OffChainTrees),
                                Round - 1, BothPrivkeys),
    VmVersion = 1,
    CallStack = [],
    CallAmount = 1,
    Update =
        aesc_offchain_update:op_call_contract(aec_id:create(account, From),
                                              aec_id:create(contract, ContractPubkey),
                                              VmVersion,
                                              CallAmount, CallData, CallStack),
    {OnChainEnv, OnChainTrees} =
        aetx_env:tx_env_and_trees_from_top(aetx_contract),
    UpdatedTrees =
        aesc_offchain_update:apply_on_trees(Update, OffChainTrees, OnChainTrees,
                                            OnChainEnv, Round, Reserve),
    StateHash = aec_trees:hash(UpdatedTrees),
    channel_force_progress_tx(ChannelPubkey, From,
                              Payload, Update, StateHash, Round, OffChainTrees).

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
				{mempool, Tx} ->
						{ok, #{tx => Tx, tx_block_hash => not_mined_yet}};
				{Hash, Tx} ->
            {ok, Header} = aec_chain:get_header(Hash),
            Height = aec_headers:height(Header),
            TopHeader = aec_chain:top_header(),
            TopHeight = aec_headers:height(TopHeader),
						{ok, #{tx => Tx,
                   tx_block_hash => Hash,
                   tx_block_height => Height,
                   key_confirmations => TopHeight - Height}}
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

-spec create_offchain_trees([{aec_keys:pubkey(), non_neg_integer()}],
                            [aect_contracts:contract()]) -> aec_trees:trees().
create_offchain_trees(Accs, Contracts) ->
    Accounts = [aec_accounts:new(Pubkey, Balance) ||
                {Pubkey, Balance} <- Accs],
    StateTreesEmpty = aec_trees:new_without_backend(),
    Set =
        fun(StateTrees0, GetterFun, SetterFun, EnterFun, Vals) ->
            Tree0 = GetterFun(StateTrees0),
            Tree1 = lists:foldl(EnterFun, Tree0, Vals),
            SetterFun(StateTrees0, Tree1)
        end,
    StateTrees1 = Set(StateTreesEmpty, fun aec_trees:accounts/1,
                      fun aec_trees:set_accounts/2,
                      fun aec_accounts_trees:enter/2,
                      Accounts),
    StateTrees2 = Set(StateTrees1, fun aec_trees:contracts/1,
                      fun aec_trees:set_contracts/2,
                      fun aect_state_tree:enter_contract/2,
                      Contracts),
    StateTrees2.

%% Private 
run(Cfg, Funs) ->
    lists:foldl(
        fun(Fun, Props) -> Fun(Props) end,
        Cfg,
        Funs).

get_channel(ChannelPubkey) ->
    Hash = aec_chain:top_block_hash(),
    {ok, Trees}  = aec_chain:get_block_state(Hash),
    Channels = aec_trees:channels(Trees),
    case aesc_state_tree:lookup(ChannelPubkey, Channels) of
        none -> error(unknown_channel);
        {value, Channel} -> Channel
    end.

off_chain_payload(ChannelId, Updates, OldStateHash, OldRound,
                  BothPrivkeys) ->
    {ok, LastOffChainTx} =
        aesc_offchain_tx:new(#{channel_id => ChannelId,
                               updates    => [], %% TODO...
                               state_hash => OldStateHash,
                               round      => OldRound}),
    {ok, SignedLastOffTx} = sign_tx(LastOffChainTx, BothPrivkeys),
    _Payload = aetx_sign:serialize_to_binary(SignedLastOffTx).

next_nonce(Pubkey) ->
    {ok, Nonce} =  aec_next_nonce:pick_for_account(Pubkey),
    Nonce.

tx_with_minimal_fee(TxSpec, Mod) ->
  tx_with_minimal_fee_(TxSpec#{fee => 0}, Mod).

tx_with_minimal_fee_(TxSpec, Mod) ->
    {ok, Tx0} = Mod:new(TxSpec),
    Header = aec_chain:top_header(),
    Height = aec_headers:height(Header),
    MinFee = aetx:min_fee(Tx0, Height),
    {ok, Tx} = Mod:new(TxSpec#{fee => MinFee}),
    case aetx:min_fee(Tx, Height) =:= MinFee of
        true -> {ok, Tx};
        false -> tx_with_minimal_fee_(TxSpec#{fee => MinFee}, Mod)
    end.

poi_and_payload(ChannelPubkey, IAmt, RAmt, Round, BothPrivkeys) ->
    ChannelId = aec_id:create(channel, ChannelPubkey),
    Channel = get_channel(ChannelPubkey),
    Initiator = aesc_channels:initiator_pubkey(Channel),
    Responder = aesc_channels:responder_pubkey(Channel),
    OffChainTrees =
        create_offchain_trees([{Initiator, IAmt}, {Responder, RAmt}], []),
    Payload = off_chain_payload(ChannelId, [], aec_trees:hash(OffChainTrees),
                                Round, BothPrivkeys),
    PoI =
        lists:foldl(
            fun(Pubkey, AccumPoI) ->
                {ok, AccumPoI1} = aec_trees:add_poi(accounts, Pubkey,
                                                    OffChainTrees, AccumPoI),
                AccumPoI1
            end,
            aec_trees:new_poi(OffChainTrees),
            [Initiator, Responder]),
    {PoI, Payload}.
