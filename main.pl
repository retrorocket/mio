#!/usr/bin/perl

use strict;
use warnings;
use utf8;
use Furl;

use Mojolicious::Lite;
use MojoX::Session::Store::Redis;
use JSON;

use String::Random;

use Crypt::CBC;

# hypnotoad設定
app->config(hypnotoad => {
	listen => ['http://*:***'],
        user => '***', #hypnotoadの実行ユーザ
        group => '***', #hypnotoadの実行グループ
});

# redis設定
plugin session => {
	stash_key => 'mojox-session',
	store	 => MojoX::Session::Store::Redis->new(
		{
			server  => '127.0.0.1:***',
			redis_prefix	=> 'mojo-session',
			redis_dbid	  => ***,
		},
	),
};

# Crypt::CBCのコンストラクタ。
my $cipher = Crypt::CBC->new(
	***
);


sub getAccessToken {
	my $self = shift;

	#Session読み込み
	my $session = $self->stash('mojox-session');
	$session->load;
	return -1 unless($session->sid && $session->data('access_token'));

	my $cipher_access_token = $session->data('access_token');
	my $access_token = $cipher->decrypt_hex($cipher_access_token);
	return $access_token;
}

get '/' => sub {
	my $self = shift;
	my $access_token = &getAccessToken($self);
	return $self->render(template => 'default') if ($access_token == -1);
	return $self->render();
} => 'index';


# mioちゃん用
my $dev_token = "***";

# クーポンの状態
get '/coupon' => sub {
	my $self = shift;
	my $access_token = &getAccessToken($self);
	return $self->render(json => {returnCode=>'error'}, status => '400') if ($access_token == -1);

	#リクエスト送信
	my $furl = Furl->new(
		headers => [
			'X-IIJmio-Developer' => $dev_token,
			'X-IIJmio-Authorization' => $access_token,
		],
		max_redirects => 0,
	);

	my $res = $furl->get('https://api.iijmio.jp/mobile/d/v1/coupon/');
	my $data = from_json( $res->content );

	return $self->render(json => $data );
} => 'coupon';


# クーポン切り替え
get '/switch' => sub {
	my $self = shift;
	my $access_token = &getAccessToken($self);
	return $self->render(json => {returnCode=>'error'}, status => '400') if ($access_token == -1);

	my $hdoServiceCode = $self->param('hdoServiceCode') || '';
	my $couponUse = $self->param('couponUse') || '';
	return $self->render(json => {returnCode=>'error'}, status => '400') unless ($hdoServiceCode && $couponUse);

	my $couponUseBool = JSON::XS::false;
	if($couponUse eq 'true'){
		$couponUseBool = JSON::XS::true;
	}

	my $hdoInfoDetail = [{ 'hdoServiceCode' => $hdoServiceCode,
					 'couponUse' => $couponUseBool }];
	my $hdoInfo = [{ 'hdoInfo' => $hdoInfoDetail }];
	my $couponInfo = { 'couponInfo' => $hdoInfo };

	my $request_json = encode_json($couponInfo);

	#リクエスト送信
	my $furl = Furl->new(
		headers => [
			'X-IIJmio-Developer' => $dev_token,
			'X-IIJmio-Authorization' => $access_token,
		],
		max_redirects => 0,
	);

	my $res = $furl->put('https://api.iijmio.jp/mobile/d/v1/coupon/',['Content-Type' => 'application/json'], $request_json );
	my $data = from_json( $res->content );

	return $self->render(json =>  $data );
} => 'switch';

# パケット使用量
get '/packet' => sub {

	my $self = shift;
	my $access_token = &getAccessToken($self);
	return $self->render(json => {returnCode=>'error'}, status => '400') if ($access_token == -1);

	#リクエスト送信
	my $furl = Furl->new(
		headers => [
			'X-IIJmio-Developer' => $dev_token,
			'X-IIJmio-Authorization' => $access_token,
		],
		max_redirects => 0,
	);

	my $res = $furl->get('https://api.iijmio.jp/mobile/d/v1/log/packet/');
	my $data = from_json( $res->content );

	return $self->render(json => $data );

} => 'packet';


# 認証
get '/auth' => sub {
	my $self = shift;

	#Session読み込み
	my $session = $self->stash('mojox-session');
	$session->load;
	return $self->redirect_to('index') if($session->sid && $session->data('access_token') );
	$session->create unless ($session->sid);

	#state生成
	my $str = $its->secret();

	#stateをSession IDと紐付け
	$session->data( state => $str );

	my $api_url="https://api.iijmio.jp/mobile/d/v1/authorization/";
	my $cb_url = $self->url_for('auth_cb')->to_abs->scheme('https');

	my $url = $self->url_for($api_url)->query (
			response_type => 'token',
			client_id => $dev_token,
			redirect_uri => $cb_url,
			state => $str);

	return $self->redirect_to( $url );

} => 'auth';

# コールバック
get '/auth_cb' => sub {
	my $self = shift;

	my $access_token = $self->param('access_token') || '';;
	my $expires_in = $self->param('expires_in') || '';
	my $state = $self->param('state') || '';
	return $self->render() unless ($access_token && $expires_in && $state);

	#Session読み込み
	my $session = $self->stash('mojox-session');
	$session->load;
	return $self->redirect_to('auth') unless ($session->sid && $session->data('state'));

	#stateチェック
	if ( $session->data('state') ne $state ){
		$session->expire;
		$session->flush;
		return $self->redirect_to('index');
	}

	#Session(redis)に格納
	my $input = $access_token;
	my $cipher_access_token = $cipher->encrypt_hex($input);
	$session->data( access_token => $cipher_access_token );

	#Sessionの有効期限更新
	$session->expires_delta($expires_in);
	$session->extend_expires; #実行しないとデフォルト3600秒のままになる

	return $self->redirect_to('index');

} => 'auth_cb';

# 強制expire
get '/logout' => sub {
	my $self = shift;

	#Session読み込み
	my $session = $self->stash('mojox-session');
	$session->load;
	return $self->render(json => {logout => 'logout'} ) unless $session->sid;
	$session->expire;
	$session->flush;
	return $self->render(json => {logout => 'logout'} );

} => 'logout';

app->start;
