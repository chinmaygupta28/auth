<?php namespace k\Auth\Contracts\Facebook;

use k\Auth\Contracts\UserInterface as BaseUserInterface;

interface UserInterface extends BaseUserInterface {

	public function setFacebookToken($token);

}