<?php namespace k\Auth\Contracts\Standard;

use k\Auth\Contracts\UserInterface as BaseUserInterface;

interface UserInterface extends BaseUserInterface {

	public function checkPassword($password);
	
}