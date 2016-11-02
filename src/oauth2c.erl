%% ----------------------------------------------------------------------------
%%
%% oauth2: Erlang OAuth 2.0 Client
%%
%% Copyright (c) 2012 KIVRA
%%
%% Permission is hereby granted, free of charge, to any person obtaining a
%% copy of this software and associated documentation files (the "Software"),
%% to deal in the Software without restriction, including without limitation
%% the rights to use, copy, modify, merge, publish, distribute, sublicense,
%% and/or sell copies of the Software, and to permit persons to whom the
%% Software is furnished to do so, subject to the following conditions:
%%
%% The above copyright notice and this permission notice shall be included in
%% all copies or substantial portions of the Software.
%%
%% THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
%% IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
%% FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
%% AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
%% LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
%% FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
%% DEALINGS IN THE SOFTWARE.
%%
%% ----------------------------------------------------------------------------

-module(oauth2c).

-export([
    retrieve_access_token/4, 
    retrieve_access_token/5, 
    retrieve_access_token/6,
    retrieve_access_token/7,
    request/3,
    request/4,
    request/5,
    request/6,
    request/7
    ]).

-record(client, {
        grant_type    = undefined :: binary() | undefined,
        auth_url      = undefined :: binary() | undefined,
        access_token  = undefined :: binary() | undefined,
        refresh_token = undefined :: binary() | undefined,
        token_type    = undefined :: token_type() | undefined,
        id            = undefined :: binary() | undefined,
        secret        = undefined :: binary() | undefined,
        scope         = undefined :: binary() | undefined,
        redirect_uri  = undefined :: binary() | undefined,
        expires_in    = undefined :: integer() | undefined,
        auth_code     = undefined :: binary() | undefined
        }).

-type method()       :: head | get | put | post | trace | options | delete.
-type url()          :: binary().
-type at_type()      :: binary(). %% <<"password">> or <<"client_credentials">>
-type headers()      :: [header()].
-type header()       :: {binary(), binary()}.
-type status_codes() :: [status_code()].
-type status_code()  :: integer().
-type reason()       :: term().
-type content_type() :: json | xml | percent.
-type property()     :: atom() | tuple().
-type proplist()     :: [property()].
-type body()         :: proplist().
%%-type response()     :: {ok, Status::status_code(), Headers::headers(), Body::body()} |
%%    {error, Status::status_code(), Headers::headers(), Body::body()} |
%%    {error, Reason::reason()}.
-type restc_response() :: {ok, Status::status_code(), Headers::headers(), Body::body()} |
                          {error, Status::status_code(), Headers::headers(), Body::body()} |
                          {error, Reason::reason()}.
-type response()       :: {restc_response(), #client{}}.
-type token_type()     :: bearer | unsupported.


-define(DEFAULT_ENCODING, json).





%%% API ========================================================================


-spec retrieve_access_token(Type, URL, ID, Secret) ->
    {ok, Headers::headers(), #client{}} | 
    {ok, Headers::headers(), #client{}, RefreshToken::binary()} | 
    {error, Reason :: binary()} when
    Type   :: at_type(),
    URL    :: url(),
    ID     :: binary(),
    Secret :: binary().
retrieve_access_token(Type, Url, ID, Secret) ->
    retrieve_access_token(Type, Url, ID, Secret, undefined,undefined,undefined).

 %           {<<"grant_type">>, Client#client.grant_type},
 %           {<<"refresh_token">>, RefreshToken},
 %           {<<"client_id">>, Id},
 %           {<<"client_secret">>, Secret}
 % url
-spec retrieve_access_token(Type,URL,ID,Secret,TokenOrScope) ->
    {ok, Headers::headers(), #client{}} | 
    {ok, Headers::headers(), #client{}, RefreshToken::binary()} | 
    {error, Reason :: binary()} when
    Type   :: at_type(),
    URL    :: url(),
    ID     :: binary(),
    Secret :: binary(),
    TokenOrScope :: binary() | undefined.

retrieve_access_token(<<"refresh_token">>,Url,ID,Secret,TokenOrScope) ->
    Client = #client{
            grant_type     = <<"refresh_token">>,
            auth_url      = Url,
            id            = ID,
            secret        = Secret,
            refresh_token = TokenOrScope
            },
    do_retrieve_access_token(Client);

retrieve_access_token(Type, Url, ID, Secret, TokenOrScope) ->
    retrieve_access_token(Type, Url, ID, Secret, TokenOrScope,undefined,undefined).

-spec retrieve_access_token(Type, URL, ID, Secret, Scope, RedirectURI) ->
    {ok, Headers::headers(), #client{}} | 
    {ok, Headers::headers(), #client{}, RefreshToken::binary()} | 
    {error, Reason :: binary()} when
    Type        :: at_type(),
    URL         :: url(),
    ID          :: binary(),
    Secret      :: binary(),
    Scope       :: binary() | undefined,
    RedirectURI :: binary() | undefined.

retrieve_access_token(Type, Url, ID, Secret, Scope, RedirectURI) ->
    retrieve_access_token(Type, Url, ID, Secret, Scope,RedirectURI,undefined).


-spec retrieve_access_token(Type, URL, ID, Secret, Scope, RedirectURI, AuthCode) ->
    {ok, Headers::headers(), #client{}} | 
    {ok, Headers::headers(), #client{}, RefreshToken::binary()} | 
    {error, Reason :: binary()} when
    Type        :: at_type(),
    URL         :: url(),
    ID          :: binary(),
    Secret      :: binary(),
    Scope       :: binary() | undefined,
    RedirectURI :: binary() | undefined,
    AuthCode    :: binary() | undefined.

retrieve_access_token(Type, Url, ID, Secret, Scope, RedirectURI, AuthCode) ->
    Client = #client{
            grant_type     = Type
            ,auth_url      = Url
            ,id            = ID
            ,secret        = Secret
            ,scope         = Scope
            ,redirect_uri  = RedirectURI
            ,auth_code     = AuthCode
            },
    do_retrieve_access_token(Client).





-spec request(Method, Url, Client) -> Response::response() when
    Method :: method(),
    Url    :: url(),
    Client :: #client{}.

request(Method, Url, Client) ->
    request(Method, ?DEFAULT_ENCODING, Url, [], [], [], Client).

-spec request(Method, Url, Expect, Client) -> Response::response() when
    Method :: method(),
    Url    :: url(),
    Expect :: status_codes(),
    Client :: #client{}.

request(Method, Url, Expect, Client) ->
    request(Method, ?DEFAULT_ENCODING, Url, Expect, [], [], Client).

-spec request(Method, Type, Url, Expect, Client) -> Response::response() when
    Method :: method(),
    Type   :: content_type(),
    Url    :: url(),
    Expect :: status_codes(),
    Client :: #client{}.

request(Method, Type, Url, Expect, Client) ->
    request(Method, Type, Url, Expect, [], [], Client).

-spec request(Method, Type, Url, Expect, Headers, Client) -> Response::response() when
    Method  :: method(),
    Type    :: content_type(),
    Url     :: url(),
    Expect  :: status_codes(),
    Headers :: headers(),
    Client  :: #client{}.
request(Method, Type, Url, Expect, Headers, Client) ->
    request(Method, Type, Url, Expect, Headers, [], Client).

-spec request(Method, Type, Url, Expect, Headers, Body, Client) -> Response::response() when
    Method  :: method(),
    Type    :: content_type(),
    Url     :: url(),
    Expect  :: status_codes(),
    Headers :: headers(),
    Body    :: body(),
    Client  :: #client{}.
request(Method, Type, Url, Expect, Headers, Body, Client) ->
    case do_request(Method, Type, Url, Expect, Headers, Body, Client) of
        {{_, 401, _, _}, Client2} ->
            {ok, _RetrHeaders, Client3} = do_retrieve_access_token(Client2),
            do_request(Method, Type, Url, Expect, Headers, Body, Client3);
        Result -> Result
    end.


%%% INTERNAL ===================================================================


do_retrieve_access_token(#client{grant_type = <<"password">>} = Client) ->
    Payload0 = [
            {<<"grant_type">>, Client#client.grant_type}
            ,{<<"username">>, Client#client.id}
            ,{<<"password">>, Client#client.secret}
            ],
    Payload = case Client#client.scope of
        undefined -> Payload0;
        Scope -> [{<<"scope">>, Scope}|Payload0]
    end,
    case restc:request(post, percent, binary_to_list(Client#client.auth_url), [200], [], Payload) of
        {ok, _, Headers, Body} ->
            AccessToken = proplists:get_value(<<"access_token">>, Body),
            RefreshToken = proplists:get_value(<<"refresh_token">>, Body),
            Result = case RefreshToken of
                undefined ->
                    #client{
                        grant_type    = Client#client.grant_type
                        ,auth_url     = Client#client.auth_url
                        ,access_token = AccessToken
                        ,id           = Client#client.id
                        ,secret       = Client#client.secret
                        ,scope        = Client#client.scope
                        };
                _ ->
                    #client{
                        grant_type     = Client#client.grant_type
                        ,auth_url      = Client#client.auth_url
                        ,access_token  = AccessToken
                        ,refresh_token = RefreshToken
                        ,scope         = Client#client.scope
                        }
            end,
            {ok, Headers, Result};
        {error, _, _, Reason} ->
            {error, Reason};
        {error, Reason} ->
            {error, Reason}
    end;

do_retrieve_access_token(#client{grant_type = <<"client_credentials">>,
                id = Id, secret = Secret} = Client) ->
    Payload0 = [{<<"grant_type">>, Client#client.grant_type}],
    Payload = case Client#client.scope of
        undefined ->
            Payload0;
        Scope ->
            [{<<"scope">>, Scope}|Payload0]
    end,
    Auth = base64:encode(<<Id/binary, ":", Secret/binary>>),
    Header = [{"Authorization", binary_to_list(<<"Basic ", Auth/binary>>)}],
    case restc:request(post, percent, binary_to_list(Client#client.auth_url),
            [200], Header, Payload) of
        {ok, _, Headers, Body} ->
            AccessToken = proplists:get_value(<<"access_token">>, Body),
            RefreshToken = proplists:get_value(<<"refresh_token">>, Body),
            TokenType = proplists:get_value(<<"token_type">>, Body, ""),
           ExpiresIn = proplists:get_value(<<"expires_in">>, B),
            Result = #client{
                    grant_type      = Client#client.grant_type
                    ,auth_url       = Client#client.auth_url
                    ,access_token   = AccessToken
                    ,refresh_token  = RefreshToken
                    ,token_type     = get_token_type(TokenType)
                     ,expires_in    =  calculate_expiry(ExpiresIn)
                    ,id             = Client#client.id
                    ,secret         = Client#client.secret
                    ,scope          = Client#client.scope
                    },
            {ok, Headers, Result};
        {error, _, _, Reason} ->
            {error, Reason};
        {error, Reason} ->
            {error, Reason}
    end;

do_retrieve_access_token(#client{
                grant_type = <<"authorization_code">>,
                id = Id, 
                secret = Secret,
                redirect_uri = RedirectURI,
                auth_code = AuthorizationCode
                } = Client) ->
    Payload = [
            {<<"grant_type">>, Client#client.grant_type},
            {<<"code">>,AuthorizationCode},
            {<<"client_id">>,Id},
            {<<"client_secret">>,Secret},
            {<<"redirect_uri">>,RedirectURI}
            ],
    
    case restc:request(post, percent, binary_to_list(Client#client.auth_url),
            [200], [], Payload) of
        {ok, _, Headers, Body} ->
            io:format("body is: ~p~n", [Body]),
            io:format("decoded body: ~p~n", [jsx:decode(Body) ]),
            B = jsx:decode(Body),
            AccessToken = proplists:get_value(<<"access_token">>, B),
            RefreshToken = proplists:get_value(<<"refresh_token">>, B),
            TokenType = proplists:get_value(<<"token_type">>, B),
            ExpiresIn = proplists:get_value(<<"expires_in">>, B),
            
            
            Result = #client{
                    grant_type      = Client#client.grant_type,
                    auth_url        = Client#client.auth_url,
                    access_token    = AccessToken,
                    refresh_token   = RefreshToken,
                    token_type      = TokenType,
                    expires_in      = calculate_expiry(ExpiresIn),
                    id              = Client#client.id,
                    secret          = Client#client.secret,
                    scope           = Client#client.scope
                    },
            {ok, Headers, Result, RefreshToken};
        {error, _, _, Reason} ->
            {error, Reason};
        {error, Reason} ->
            {error, Reason}
    end;

do_retrieve_access_token(#client{
                grant_type = <<"refresh_token">>,
                id = Id, 
                secret = Secret,
                refresh_token = RefreshToken
                } = Client) ->
    Payload = [
            {<<"grant_type">>, Client#client.grant_type},
            {<<"refresh_token">>, RefreshToken},
            {<<"client_id">>, Id},
            {<<"client_secret">>, Secret}
            ],
    
    case restc:request(post, percent, binary_to_list(Client#client.auth_url),
            [200], [], Payload) of
        {ok, _, Headers, Body} ->
            B = jsx:decode(Body),
            AccessToken = proplists:get_value(<<"access_token">>, B),
            TokenType = proplists:get_value(<<"token_type">>, B),
            ExpiresIn = proplists:get_value(<<"expires_in">>, B),
            
            Result = #client{
                    grant_type      = Client#client.grant_type,
                    auth_url        = Client#client.auth_url,
                    access_token    = AccessToken,
                    token_type      = TokenType,
                    refresh_token   = RefreshToken,
                    expires_in      = calculate_expiry(ExpiresIn),
                    id              = Client#client.id,
                    secret          = Client#client.secret,
                    scope           = Client#client.scope
                    },
            {ok, Headers, Result};
        {error, _, _, Reason} ->
            {error, Reason};
        {error, Reason} ->
            {error, Reason}
    end.

-spec get_token_type(binary()) -> token_type().
get_token_type(Type) ->
    get_str_token_type(string:to_lower(binary_to_list(Type))).

-spec get_str_token_type(string()) -> token_type().
get_str_token_type("bearer") -> bearer;
get_str_token_type(_Else) -> unsupported.

do_request(Method, Type, Url, Expect, Headers, Body, Client) ->
    Client2 = check_expired(Client),
    Headers2 = add_auth_header(Headers, Client2),
    {restc:request(Method, Type, binary_to_list(Url), Expect, Headers2, Body), Client2}.

-spec add_auth_header(headers(),#client{}) -> headers().
add_auth_header(Headers, #client{access_token = AccessToken,token_type = TokenType}) ->
    Prefix = autorization_prefix(TokenType),
    AH = {"Authorization", binary_to_list(<<Prefix/binary, " ", AccessToken/binary>>)},
    [AH | proplists:delete("Authorization", Headers)].

-spec calculate_expiry(undefined|integer()) -> integer().
calculate_expiry(undefined) ->
   calculate_expiry(60000);
calculate_expiry(Seconds) ->
    Now = calendar:datetime_to_gregorian_seconds(calendar:universal_time()),
    Now + Seconds.

-spec check_expired(#client{}) -> #client{}.
check_expired(#client{expires_in = ExpiresIn} = Client) ->
    Now = calendar:datetime_to_gregorian_seconds(calendar:universal_time()),    
    Test = ((ExpiresIn - Now) > 0),
    case Test of
        true -> Client;
        false -> TmpClient = #client{
                    grant_type    = <<"refresh_token">>,
                    auth_url      = Client#client.auth_url,
                    refresh_token = Client#client.refresh_token,
                    id            = Client#client.id,
                    secret        = Client#client.secret,
                    scope         = Client#client.scope
                    },
            {ok, _, C} = do_retrieve_access_token(TmpClient),
            C   
    end.

-spec autorization_prefix(token_type()) -> binary().
autorization_prefix(bearer) -> <<"Bearer">>;
autorization_prefix(unsupported) -> <<"token">>.
