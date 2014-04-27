<?php namespace k\Auth\Contracts\Facebook;

use k\Auth\Contracts\UserRepositoryInterface as BaseUserRepositoryInterface;

interface UserRepositoryInterface extends BaseUserRepositoryInterface {

	public function findByFacebookData($data);

	public function createFromFacebookData($data);

}