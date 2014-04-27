<?php namespace k\Auth\Contracts;

interface HttpClientInterface {

	const facebookApiOrigin = 'https://graph.facebook.com';

	public function fetchLongLivedFacebookToken($token, $clientId, $clientSecret);

	public function fetchFacebookUserData($token);

}